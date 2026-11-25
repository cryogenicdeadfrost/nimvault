## ECDSA P-256 key pair & self-signed X.509 v3 certificate generator.
## Uses BearSSL's audited OS CSPRNG + EC P-256 + RFC 6979 ECDSA-SHA256 signing.

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
    organization: "nimvault-dev",
    sanDnsNames: @[commonName],
    validDays: 365,
    isCA: true
  )

proc buildRdnName(cn, org: string): seq[byte] =
  var rdns: seq[seq[byte]] = @[]
  if org.len > 0:
    rdns.add(derSet(derSeq(derOid("2.5.4.10"), derUtf8String(org))))
  if cn.len > 0:
    rdns.add(derSet(derSeq(derOid("2.5.4.3"), derUtf8String(cn))))
  derSeq(rdns)

proc buildSanExtension(dnsNames: seq[string]): seq[byte] =
  var entries: seq[seq[byte]] = @[]
  for name in dnsNames:
    let trimmed = name.strip()
    if trimmed.len > 0:
      var bytes = newSeq[byte](trimmed.len)
      copyMem(addr bytes[0], unsafeAddr trimmed[0], trimmed.len)
      entries.add(derWrap(0x82'u8, bytes)) # dNSName [2] IMPLICIT IA5String
  let sanVal = derSeq(entries)
  derSeq(derOid("2.5.29.17"), derOctetString(sanVal))

proc buildBasicConstraintsExt(isCA: bool): seq[byte] =
  let bcVal = if isCA: derSeq(derBool(true)) else: derSeq()
  derSeq(derOid("2.5.29.19"), derBool(true), derOctetString(bcVal))

proc buildKeyUsageExt(isCA: bool): seq[byte] =
  # BIT STRING: digitalSignature (bit 0 = 0x80), keyEncipherment (bit 2 = 0x20),
  # keyCertSign (bit 5 = 0x04), cRLSign (bit 6 = 0x02)
  let bits: byte = if isCA: 0x80'u8 or 0x04'u8 or 0x02'u8 else: 0x80'u8
  let unusedBits: byte = if isCA: 1'u8 else: 7'u8
  let kuVal = derWrap(0x03'u8, @[unusedBits, bits])
  derSeq(derOid("2.5.29.15"), derBool(true), derOctetString(kuVal))

proc generateSelfSignedEcP256*(opts: KeygenOptions): VaultResult[GeneratedCertBundle] =
  ## Generates a fresh ECDSA P-256 private key (PKCS#8 PEM) and a self-signed
  ## X.509 v3 certificate (PEM) signed with ecdsa-with-SHA256.
  if opts.commonName.len == 0:
    return err[GeneratedCertBundle](veKeygenFailed, "Common Name (CN) cannot be empty")
  if opts.validDays <= 0:
    return err[GeneratedCertBundle](veKeygenFailed, "validDays must be > 0")

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
    return err[GeneratedCertBundle](
      veKeygenFailed,
      "Failed to generate ECDSA P-256 keypair via OS CSPRNG"
    )

  # Generate random positive 16-byte serial number
  var serial: array[16, byte]
  if nv_random_bytes(addr serial[0], 16) == 0:
    return err[GeneratedCertBundle](veKeygenFailed, "OS CSPRNG failed for certificate serial")
  serial[0] = (serial[0] and 0x7f'u8) or 0x01'u8 # positive, non-zero MSB

  let nowUtc = now().utc
  let notBefore = nowUtc - initDuration(minutes = 5)
  let notAfter = nowUtc + initDuration(days = opts.validDays)

  let sigAlgId = derSeq(derOid("1.2.840.10045.4.3.2")) # ecdsa-with-SHA256
  let nameDer = buildRdnName(opts.commonName, opts.organization)
  let validityDer = derSeq(derUtcTime(notBefore), derUtcTime(notAfter))
  let spkiDer = derSeq(
    derSeq(derOid("1.2.840.10045.2.1"), derOid("1.2.840.10045.3.1.7")),
    derBitString(pubRaw[0 ..< int(pubLen)])
  )

  var exts: seq[seq[byte]] = @[
    buildBasicConstraintsExt(opts.isCA),
    buildKeyUsageExt(opts.isCA)
  ]
  var sans = opts.sanDnsNames
  if sans.len == 0:
    sans = @[opts.commonName]
  exts.add(buildSanExtension(sans))
  let extensionsDer = derContext(3'u8, derSeq(exts), constructed = true)

  let tbsCert = derSeq(
    derContext(0'u8, derSmallInt(2), constructed = true), # v3 = 2
    derInt(serial),
    sigAlgId,
    nameDer,
    validityDer,
    nameDer,
    spkiDer,
    extensionsDer
  )

  # Sign SHA-256(tbsCert) with ECDSA P-256 (ASN.1 DER signature)
  var digest = sha256Digest(tbsCert)
  var sigBuf: array[80, byte]
  let sigLen = nv_ecdsa_sign_p256_sha256(
    addr privRaw[0], privLen,
    addr digest[0],
    addr sigBuf[0], csize_t(sigBuf.len)
  )
  if sigLen == 0:
    return err[GeneratedCertBundle](veKeygenFailed, "ECDSA P-256 signing failed")

  let certDer = derSeq(
    tbsCert,
    sigAlgId,
    derBitString(sigBuf[0 ..< int(sigLen)])
  )

  let parsed = parseCertDer(certDer)
  if not parsed.isOk:
    return err[GeneratedCertBundle](
      veKeygenFailed,
      "Generated certificate failed self-parse sanity check: " & parsed.err.message
    )

  ok(GeneratedCertBundle(
    privateKeyPem: encodePem("PRIVATE KEY", pkcs8Der[0 ..< int(pkcs8Len)]),
    certificatePem: encodePem("CERTIFICATE", certDer),
    certInfo: parsed.val
  ))
