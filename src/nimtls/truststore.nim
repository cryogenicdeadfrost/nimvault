# Tiered CA root resolver: explicit file -> env var -> OS store -> baked Mozilla bundle.

import std/[os, strutils]
import ./errors
import ./x509

when defined(macosx):
  import std/osproc

type
  TrustSourceKind* = enum
    tsExplicitFile
    tsEnvVar
    tsSystemStore
    tsEmbeddedRoots

  TrustBundle* = object
    pemData*: string
    sourcePath*: string
    sourceKind*: TrustSourceKind
    certCount*: int

when defined(nimtlsEmbedRoots):
  const EmbeddedMozillaRoots* = staticRead("./vendor/cacert.pem")

proc hasEmbeddedRoots*(): bool {.inline.} =
  when defined(nimtlsEmbedRoots): true else: false

proc bakedRoots*(): TlsResult[TrustBundle] =
  when defined(nimtlsEmbedRoots):
    let n = countPemCerts(EmbeddedMozillaRoots)
    if n <= 0:
      return err[TrustBundle](
        teTrustStoreInvalid,
        "Embedded Mozilla CA bundle has 0 certs",
        likelyCause = "src/nimtls/vendor/cacert.pem is empty or broken.",
        suggestion = "Re-fetch cacert.pem from https://curl.se/ca/cacert.pem."
      )
    ok(TrustBundle(
      pemData: EmbeddedMozillaRoots,
      sourcePath: "embedded:mozilla-ca-bundle",
      sourceKind: tsEmbeddedRoots,
      certCount: n
    ))
  else:
    err[TrustBundle](
      teTrustStoreNotFound,
      "Embedded root certificates were not compiled in",
      likelyCause = "Built without `-d:nimtlsEmbedRoots`.",
      suggestion = "Rebuild with `-d:nimtlsEmbedRoots` to bake in Mozilla roots (~200 KB)."
    )

proc loadEmbeddedTrustStore*(): TlsResult[TrustBundle] {.inline.} = bakedRoots()

proc snagPemFile(path: string, kind = tsExplicitFile): TlsResult[TrustBundle] =
  if path.len == 0:
    return err[TrustBundle](teTrustStoreInvalid, "CA bundle path is empty")
  if not fileExists(path):
    return err[TrustBundle](
      teTrustStoreNotFound,
      "CA bundle file not found: " & path,
      likelyCause = "File doesn't exist or isn't readable.",
      suggestion = "Check the path or unset SSL_CERT_FILE to use OS/embedded roots."
    )
  try:
    let pem = readFile(path)
    let n = countPemCerts(pem)
    if n <= 0:
      return err[TrustBundle](
        teTrustStoreInvalid,
        "No PEM certificates found in: " & path,
        likelyCause = "File has no `-----BEGIN CERTIFICATE-----` blocks.",
        suggestion = "Point to a valid PEM CA bundle."
      )
    ok(TrustBundle(pemData: pem, sourcePath: path, sourceKind: kind, certCount: n))
  except CatchableError as e:
    err[TrustBundle](
      teTrustStoreInvalid,
      "Failed reading CA bundle '" & path & "': " & e.msg,
      likelyCause = "Permissions or I/O error.",
      suggestion = "Check file permissions."
    )

proc loadTrustFile*(path: string, kind = tsExplicitFile): TlsResult[TrustBundle] {.inline.} =
  snagPemFile(path, kind)

when defined(windows):
  type
    HCERTSTORE = pointer
    CERT_CONTEXT {.pure.} = object
      dwCertEncodingType: uint32
      pbCertEncoded: ptr UncheckedArray[byte]
      cbCertEncoded: uint32
      pCertInfo: pointer
      hCertStore: HCERTSTORE
    PCCERT_CONTEXT = ptr CERT_CONTEXT

  # crypt32.dll ships on every Windows box since Win2K, so dynlib here costs zero extra deployment files
  proc certOpenSystemStoreA(hProv: uint, szSubsystemProtocol: cstring): HCERTSTORE
    {.stdcall, dynlib: "crypt32.dll", importc: "CertOpenSystemStoreA".}
  proc certEnumCertificatesInStore(hCertStore: HCERTSTORE, pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT
    {.stdcall, dynlib: "crypt32.dll", importc: "CertEnumCertificatesInStore".}
  proc certCloseStore(hCertStore: HCERTSTORE, dwFlags: uint32): int32
    {.stdcall, dynlib: "crypt32.dll", importc: "CertCloseStore".}

  proc sniffSystemRoots(): TlsResult[TrustBundle] =
    let store = certOpenSystemStoreA(0, "ROOT")
    if store == nil:
      return err[TrustBundle](
        teTrustStoreNotFound,
        "Could not open Windows CryptoAPI ROOT store",
        likelyCause = "CryptoAPI is blocked or restricted in this sandbox.",
        suggestion = "Compile with `-d:nimtlsEmbedRoots` or set `SSL_CERT_FILE`."
      )
    defer: discard certCloseStore(store, 0)

    var pemOut = newStringOfCap(131072)
    var count = 0
    var ctx: PCCERT_CONTEXT = nil
    while true:
      ctx = certEnumCertificatesInStore(store, ctx)
      if ctx == nil: break
      if ctx.pbCertEncoded != nil and ctx.cbCertEncoded > 0'u32:
        let derLen = int(ctx.cbCertEncoded)
        var der = newSeq[byte](derLen)
        copyMem(addr der[0], ctx.pbCertEncoded, derLen)
        pemOut.add(encodePem("CERTIFICATE", der))
        inc count

    if count == 0:
      return err[TrustBundle](
        teTrustStoreNotFound,
        "Windows CryptoAPI ROOT store returned 0 certs",
        likelyCause = "Sandboxed or stripped Windows environment.",
        suggestion = "Compile with `-d:nimtlsEmbedRoots` or set `SSL_CERT_FILE`."
      )

    ok(TrustBundle(
      pemData: pemOut,
      sourcePath: "windows:CryptoAPI:ROOT",
      sourceKind: tsSystemStore,
      certCount: count
    ))

elif defined(macosx):
  proc sniffSystemRoots(): TlsResult[TrustBundle] =
    if fileExists("/etc/ssl/cert.pem"):
      let res = snagPemFile("/etc/ssl/cert.pem", tsSystemStore)
      if res.isOk: return res
    try:
      let (output, exitCode) = execCmdEx(
        "/usr/bin/security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain"
      )
      if exitCode == 0:
        let n = countPemCerts(output)
        if n > 0:
          return ok(TrustBundle(
            pemData: output,
            sourcePath: "macos:SystemRootCertificates.keychain",
            sourceKind: tsSystemStore,
            certCount: n
          ))
    except CatchableError:
      discard
    err[TrustBundle](
      teTrustStoreNotFound,
      "No macOS system CA certs found",
      likelyCause = "Neither /etc/ssl/cert.pem nor SystemRootCertificates.keychain was readable.",
      suggestion = "Compile with `-d:nimtlsEmbedRoots` or set `SSL_CERT_FILE`."
    )

else:
  const UnixBundlePaths = [
    "/etc/ssl/certs/ca-certificates.crt",                  # Debian/Ubuntu/Alpine/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",                    # Fedora/RHEL/CentOS
    "/etc/ssl/ca-bundle.pem",                              # openSUSE
    "/etc/pki/tls/cacert.pem",                             # OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",   # RHEL/CentOS 7+
    "/etc/ssl/cert.pem",                                   # Alpine/OpenBSD
    "/usr/local/share/certs/ca-root-nss.crt",              # FreeBSD
    "/etc/openssl/certs/ca-certificates.crt"               # NetBSD
  ]

  proc sniffSystemRoots(): TlsResult[TrustBundle] =
    for path in UnixBundlePaths:
      if fileExists(path):
        let res = snagPemFile(path, tsSystemStore)
        if res.isOk: return res
    err[TrustBundle](
      teTrustStoreNotFound,
      "No system CA bundle found on this host",
      likelyCause = "Minimal image (Alpine/distroless/FROM scratch) missing `ca-certificates`.",
      suggestion = "Compile with `-d:nimtlsEmbedRoots` or set `SSL_CERT_FILE`."
    )

proc loadSystemTrustStore*(): TlsResult[TrustBundle] {.inline.} = sniffSystemRoots()

proc resolveTrustStore*(explicitPath = "", allowEmbeddedFallback = true): TlsResult[TrustBundle] =
  # Explicit path fails loud on purpose -- silently falling back when the caller asked for a specific CA is a security footgun
  if explicitPath.len > 0:
    return snagPemFile(explicitPath, tsExplicitFile)

  for envName in ["SSL_CERT_FILE", "NIMTLS_CA_BUNDLE"]:
    let envPath = getEnv(envName).strip()
    if envPath.len > 0:
      return snagPemFile(envPath, tsEnvVar)

  let osRes = sniffSystemRoots()
  if osRes.isOk:
    when defined(nimtlsEmbedRoots):
      # OS trust stores can lag behind newer public roots (Windows lazy AutoRootCtl,
      # older macOS /etc/ssl/cert.pem, stale Linux images). When embedded roots are
      # compiled in, union OS roots (keeps corporate CAs) with the baked Mozilla set.
      if allowEmbeddedFallback:
        let emb = bakedRoots()
        if emb.isOk:
          return ok(TrustBundle(
            pemData: osRes.val.pemData & "\n" & emb.val.pemData,
            sourcePath: osRes.val.sourcePath & "+embedded:mozilla-ca-bundle",
            sourceKind: tsSystemStore,
            certCount: osRes.val.certCount + emb.val.certCount
          ))
    return osRes

  if allowEmbeddedFallback:
    when defined(nimtlsEmbedRoots):
      return bakedRoots()

  err[TrustBundle](
    teTrustStoreNotFound,
    "No CA root certificates could be resolved (" & osRes.err.message & ")",
    likelyCause = "No SSL_CERT_FILE, no OS trust store, and no embedded roots.",
    suggestion = "Recompile with `-d:nimtlsEmbedRoots` or set `SSL_CERT_FILE=/path/to/cacert.pem`."
  )
