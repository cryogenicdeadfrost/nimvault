## Tiered CA Root Trust Store Resolution
##
## Resolution priority:
##   1. Explicit CA bundle path (if supplied)
##   2. Environment variable: SSL_CERT_FILE (or NIMVAULT_CA_BUNDLE)
##   3. Native OS trust store:
##        - Windows: CryptoAPI ROOT store (crypt32.dll)
##        - Linux/BSD: Standard system CA bundle paths
##        - macOS: /etc/ssl/cert.pem or SystemRootCertificates.keychain
##   4. Compile-time embedded Mozilla CA bundle (-d:nimvaultEmbedRoots via staticRead)

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

when defined(nimvaultEmbedRoots):
  const EmbeddedMozillaRoots* = staticRead("../../vendor/cacert.pem")

proc hasEmbeddedRoots*(): bool {.inline.} =
  ## Returns true if this binary was compiled with -d:nimvaultEmbedRoots.
  when defined(nimvaultEmbedRoots):
    true
  else:
    false

proc loadEmbeddedTrustStore*(): VaultResult[TrustBundle] =
  ## Explicitly loads the compile-time embedded Mozilla CA bundle.
  when defined(nimvaultEmbedRoots):
    let count = countPemCerts(EmbeddedMozillaRoots)
    if count <= 0:
      return err[TrustBundle](
        veTrustStoreInvalid,
        "Embedded Mozilla CA bundle contains no certificates",
        likelyCause = "vendor/cacert.pem appears empty or malformed.",
        suggestion = "Refresh vendor/cacert.pem from https://curl.se/ca/cacert.pem."
      )
    ok(TrustBundle(
      pemData: EmbeddedMozillaRoots,
      sourcePath: "embedded:mozilla-ca-bundle",
      sourceKind: tsEmbeddedRoots,
      certCount: count
    ))
  else:
    err[TrustBundle](
      veTrustStoreNotFound,
      "Embedded root certificates were not compiled into this binary",
      likelyCause = "Binary was compiled without `-d:nimvaultEmbedRoots`.",
      suggestion = "Recompile with `-d:nimvaultEmbedRoots` to bundle Mozilla CA roots (~200KB)."
    )

proc loadTrustFile*(path: string, kind = tsExplicitFile): VaultResult[TrustBundle] =
  ## Loads a PEM CA bundle file from disk and validates it contains at least one certificate.
  if path.len == 0:
    return err[TrustBundle](veTrustStoreInvalid, "CA bundle path is empty")
  if not fileExists(path):
    return err[TrustBundle](
      veTrustStoreNotFound,
      "CA bundle file not found: " & path,
      likelyCause = "The configured CA file path does not exist or is inaccessible.",
      suggestion = "Check the path or unset SSL_CERT_FILE to fall back to OS/embedded roots."
    )
  try:
    let pem = readFile(path)
    let count = countPemCerts(pem)
    if count <= 0:
      return err[TrustBundle](
        veTrustStoreInvalid,
        "No PEM certificates found in: " & path,
        likelyCause = "The file is empty or does not contain `-----BEGIN CERTIFICATE-----` blocks.",
        suggestion = "Provide a valid PEM-formatted CA bundle file."
      )
    ok(TrustBundle(
      pemData: pem,
      sourcePath: path,
      sourceKind: kind,
      certCount: count
    ))
  except CatchableError as e:
    err[TrustBundle](
      veTrustStoreInvalid,
      "Failed to read CA bundle '" & path & "': " & e.msg,
      likelyCause = "Insufficient file permissions or I/O error.",
      suggestion = "Verify read permissions on the CA bundle file."
    )

# ---------------------------------------------------------------------------
# Platform-specific native OS trust store discovery
# ---------------------------------------------------------------------------

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

  proc certOpenSystemStoreA(hProv: uint, szSubsystemProtocol: cstring): HCERTSTORE
    {.stdcall, dynlib: "crypt32.dll", importc: "CertOpenSystemStoreA".}
  proc certEnumCertificatesInStore(hCertStore: HCERTSTORE, pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT
    {.stdcall, dynlib: "crypt32.dll", importc: "CertEnumCertificatesInStore".}
  proc certCloseStore(hCertStore: HCERTSTORE, dwFlags: uint32): int32
    {.stdcall, dynlib: "crypt32.dll", importc: "CertCloseStore".}

  proc loadSystemTrustStore*(): VaultResult[TrustBundle] =
    ## Loads root CA certificates directly from Windows CryptoAPI "ROOT" store.
    let store = certOpenSystemStoreA(0, "ROOT")
    if store == nil:
      return err[TrustBundle](
        veTrustStoreNotFound,
        "Unable to open Windows CryptoAPI ROOT certificate store",
        likelyCause = "CryptoAPI access is restricted or unavailable in this environment.",
        suggestion = "Compile with `-d:nimvaultEmbedRoots` or set `SSL_CERT_FILE`."
      )
    defer:
      discard certCloseStore(store, 0)

    var pemOut = newStringOfCap(131072)
    var count = 0
    var ctx: PCCERT_CONTEXT = nil
    while true:
      ctx = certEnumCertificatesInStore(store, ctx)
      if ctx == nil:
        break
      if ctx.pbCertEncoded != nil and ctx.cbCertEncoded > 0'u32:
        let derLen = int(ctx.cbCertEncoded)
        var der = newSeq[byte](derLen)
        copyMem(addr der[0], ctx.pbCertEncoded, derLen)
        pemOut.add(encodePem("CERTIFICATE", der))
        inc count

    if count == 0:
      return err[TrustBundle](
        veTrustStoreNotFound,
        "Windows CryptoAPI ROOT store returned 0 certificates",
        likelyCause = "Sandboxed or stripped Windows environment with no accessible system roots.",
        suggestion = "Compile with `-d:nimvaultEmbedRoots` or set `SSL_CERT_FILE`."
      )

    ok(TrustBundle(
      pemData: pemOut,
      sourcePath: "windows:CryptoAPI:ROOT",
      sourceKind: tsSystemStore,
      certCount: count
    ))

elif defined(macosx):
  proc loadSystemTrustStore*(): VaultResult[TrustBundle] =
    ## Loads root CA certificates from macOS /etc/ssl/cert.pem or SystemRootCertificates.keychain.
    if fileExists("/etc/ssl/cert.pem"):
      let res = loadTrustFile("/etc/ssl/cert.pem", tsSystemStore)
      if res.isOk:
        return res
    try:
      let (output, exitCode) = execCmdEx(
        "/usr/bin/security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain"
      )
      if exitCode == 0:
        let count = countPemCerts(output)
        if count > 0:
          return ok(TrustBundle(
            pemData: output,
            sourcePath: "macos:SystemRootCertificates.keychain",
            sourceKind: tsSystemStore,
            certCount: count
          ))
    except CatchableError:
      discard
    err[TrustBundle](
      veTrustStoreNotFound,
      "No macOS system CA certificates found",
      likelyCause = "Neither /etc/ssl/cert.pem nor macOS SystemRootCertificates.keychain was accessible.",
      suggestion = "Compile with `-d:nimvaultEmbedRoots` or set `SSL_CERT_FILE`."
    )

else:
  const UnixCaBundlePaths = [
    "/etc/ssl/certs/ca-certificates.crt",                  # Debian/Ubuntu/Alpine/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",                    # Fedora/RHEL/CentOS
    "/etc/ssl/ca-bundle.pem",                              # OpenSUSE
    "/etc/pki/tls/cacert.pem",                             # OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",   # RHEL/CentOS 7+
    "/etc/ssl/cert.pem",                                   # Alpine/OpenBSD/macOS
    "/usr/local/share/certs/ca-root-nss.crt",              # FreeBSD
    "/etc/openssl/certs/ca-certificates.crt"               # NetBSD
  ]

  proc loadSystemTrustStore*(): VaultResult[TrustBundle] =
    ## Discovers standard Linux/Unix system CA certificate bundles.
    for path in UnixCaBundlePaths:
      if fileExists(path):
        let res = loadTrustFile(path, tsSystemStore)
        if res.isOk:
          return res
    err[TrustBundle](
      veTrustStoreNotFound,
      "No system CA certificate bundle found on this host",
      likelyCause = "Minimal container (e.g. Alpine/distroless/FROM scratch) missing `ca-certificates` package.",
      suggestion = "Compile with `-d:nimvaultEmbedRoots` for zero-dependency embedded Mozilla roots, or set `SSL_CERT_FILE`."
    )

proc resolveTrustStore*(explicitPath = "", allowEmbeddedFallback = true): VaultResult[TrustBundle] =
  ## Tiered Trust Resolution:
  ##   1. Explicit path (strict: fails immediately if invalid)
  ##   2. SSL_CERT_FILE / NIMVAULT_CA_BUNDLE environment variables
  ##   3. Native OS trust store
  ##   4. Compile-time embedded Mozilla CA bundle (when -d:nimvaultEmbedRoots)
  if explicitPath.len > 0:
    return loadTrustFile(explicitPath, tsExplicitFile)

  for envName in ["SSL_CERT_FILE", "NIMVAULT_CA_BUNDLE"]:
    let envPath = getEnv(envName).strip()
    if envPath.len > 0:
      return loadTrustFile(envPath, tsEnvVar)

  let osRes = loadSystemTrustStore()
  if osRes.isOk:
    return osRes

  if allowEmbeddedFallback:
    when defined(nimvaultEmbedRoots):
      return loadEmbeddedTrustStore()

  err[TrustBundle](
    veTrustStoreNotFound,
    "No CA root certificates could be resolved (" & osRes.err.message & ")",
    likelyCause = "Neither SSL_CERT_FILE, native OS trust store, nor embedded CA roots were available.",
    suggestion = "Recompile with `-d:nimvaultEmbedRoots` to bundle Mozilla roots, or set `SSL_CERT_FILE=/path/to/cacert.pem`."
  )
