# ECDSA P-256 keygen + self-signed X.509 v3 cert builder backed by BearSSL's OS CSPRNG.

import std/[times, strutils]
import ./errors
import ./x509
import ./backend_bearssl

type
  KeygenOptions* = object
    commonName*: string
    organization*: string
    sanDnsNames*: seq[string]
    validDays*: int
    isCA*: bool

  GeneratedCertBundle* = object
    privateKeyPem*: string
    certificatePem*: string
    certInfo*: CertInfo

proc defaultKeygenOptions*(commonName = "localhost"): KeygenOptions =
  KeygenOptions(
    commonName: commonName,
    organization: "nimtls-dev",
    sanDnsNames: @[commonName],
    validDays: 365,
    isCA: true
  )

proc packRdn(cn, org: string): seq[byte] =
  var rdns: seq[seq[byte]] = @[]
  if org.len > 0: rdns.add(derSet(derSeq(derOid("2.5.4.10"), derUtf8String(org))))
  if cn.len > 0:  rdns.add(derSet(derSeq(derOid("2.5.4.3"), derUtf8String(cn))))
  derSeq(rdns)

proc packSans(dnsNames: seq[string]): seq[byte] =
  var entries: seq[seq[byte]] = @[]
  for name in dnsNames:
    let trimmed = name.strip()
    if trimmed.len > 0:
      var bytes = newSeq[byte](trimmed.len)
      copyMem(addr bytes[0], unsafeAddr trimmed[0], trimmed.len)
      entries.add(derWrap(0x82'u8, bytes)) # dNSName [2]
  derSeq(derOid("2.5.29.17"), derOctetString(derSeq(entries)))

proc packBc(isCA: bool): seq[byte] =
  let bcVal = if isCA: derSeq(derBool(true)) else: derSeq()
  derSeq(derOid("2.5.29.19"), derBool(true), derOctetString(bcVal))

proc packKeyUsage(isCA: bool): seq[byte] =
  # digitalSignature (0x80) + optional keyCertSign (0x04) + cRLSign (0x02)
  let bits: byte = if isCA: 0x80'u8 or 0x04'u8 or 0x02'u8 else: 0x80'u8
  let unusedBits: byte = if isCA: 1'u8 else: 7'u8
  derSeq(derOid("2.5.29.15"), derBool(true), derOctetString(derWrap(0x03'u8, @[unusedBits, bits])))

proc mintSelfSigned*(opts: KeygenOptions): TlsResult[GeneratedCertBundle] =
  if opts.commonName.len == 0:
    return err[GeneratedCertBundle](teKeygenFailed, "Common Name (CN) cannot be empty")
  if opts.validDays <= 0:
    return err[GeneratedCertBundle](teKeygenFailed, "validDays must be > 0")

  var privRaw: array[32, byte]
  var privLen: csize_t = 32
  var pubRaw: array[65, byte]
  var pubLen: csize_t = 65
  var pkcs8Der: array[256, byte]
  var pkcs8Len: csize_t = 256

  if nv_ec_keygen_p256(
    addr privRaw[0], addr privLen,
    addr pubRaw[0], addr pubLen,
    addr pkcs8Der[0], addr pkcs8Len
  ) == 0:
    return err[GeneratedCertBundle](teKeygenFailed, "OS CSPRNG ECDSA P-256 keygen failed")

  var serial: array[16, byte]
  if nv_random_bytes(addr serial[0], 16) == 0:
    return err[GeneratedCertBundle](teKeygenFailed, "OS CSPRNG failed for cert serial")
  serial[0] = (serial[0] and 0x7f'u8) or 0x01'u8 # keep ASN.1 INTEGER positive & non-zero

  let nowUtc = now().utc
  let notBefore = nowUtc - initDuration(minutes = 5)
  let notAfter = nowUtc + initDuration(days = opts.validDays)

  let sigAlgId = derSeq(derOid("1.2.840.10045.4.3.2")) # ecdsa-with-SHA256
  let nameDer = packRdn(opts.commonName, opts.organization)
  let validityDer = derSeq(derUtcTime(notBefore), derUtcTime(notAfter))
  let spkiDer = derSeq(
    derSeq(derOid("1.2.840.10045.2.1"), derOid("1.2.840.10045.3.1.7")),
    derBitString(pubRaw[0 ..< int(pubLen)])
  )

  var sans = opts.sanDnsNames
  if sans.len == 0: sans = @[opts.commonName]
  let extsDer = derContext(3'u8, derSeq(@[
    packBc(opts.isCA),
    packKeyUsage(opts.isCA),
    packSans(sans)
  ]), constructed = true)

  let tbsCert = derSeq(
    derContext(0'u8, derSmallInt(2), constructed = true),
    derInt(serial),
    sigAlgId,
    nameDer,
    validityDer,
    nameDer,
    spkiDer,
    extsDer
  )

  var digest = sha256Digest(tbsCert)
  var sigBuf: array[80, byte]
  let sigLen = nv_ecdsa_sign_p256_sha256(
    addr privRaw[0], privLen,
    addr digest[0],
    addr sigBuf[0], csize_t(sigBuf.len)
  )
  if sigLen == 0:
    return err[GeneratedCertBundle](teKeygenFailed, "ECDSA P-256 signing failed")

  let certDer = derSeq(tbsCert, sigAlgId, derBitString(sigBuf[0 ..< int(sigLen)]))
  let parsed = parseCertDer(certDer)
  if not parsed.isOk:
    return err[GeneratedCertBundle](teKeygenFailed, "Self-parse failed on generated cert: " & parsed.err.message)

  ok(GeneratedCertBundle(
    privateKeyPem: encodePem("PRIVATE KEY", pkcs8Der[0 ..< int(pkcs8Len)]),
    certificatePem: encodePem("CERTIFICATE", certDer),
    certInfo: parsed.val
  ))

proc generateSelfSignedEcP256*(opts: KeygenOptions): TlsResult[GeneratedCertBundle] {.inline.} =
  mintSelfSigned(opts)
