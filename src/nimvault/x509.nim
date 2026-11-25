## Pure Nim PEM codec, SHA-256 fingerprint, ASN.1 DER encoder/decoder,
## and X.509 certificate metadata inspector.

import std/[base64, strutils, times]
import ./errors

type
  PemBlock* = object
    label*: string
    data*: seq[byte]

  CertInfo* = object
    version*: int
    serialHex*: string
    subject*: string
    subjectCN*: string
    issuer*: string
    issuerCN*: string
    notBefore*: string
    notAfter*: string
    notBeforeEpoch*: int64
    notAfterEpoch*: int64
    sanDnsNames*: seq[string]
    sanIps*: seq[string]
    isCA*: bool
    keyAlgorithm*: string
    sigAlgorithm*: string
    sha256Fingerprint*: string
    derLen*: int

# ---------------------------------------------------------------------------
# Pure Nim SHA-256 (FIPS 180-4) for certificate fingerprints & self-signing
# ---------------------------------------------------------------------------

const sha256K: array[64, uint32] = [
  0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
  0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
  0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
  0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
  0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
  0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
  0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
  0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
  0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
  0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
  0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
  0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
  0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
  0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
  0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
  0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
]

proc rotr32(x: uint32, n: uint32): uint32 {.inline.} =
  (x shr n) or (x shl (32'u32 - n))

proc sha256Digest*(data: openArray[byte]): array[32, byte] =
  var h: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  let bitLen = uint64(data.len) * 8'u64
  var msg = newSeq[byte](data.len + 1)
  if data.len > 0:
    copyMem(addr msg[0], unsafeAddr data[0], data.len)
  msg[data.len] = 0x80'u8
  while (msg.len mod 64) != 56:
    msg.add(0'u8)
  for i in countdown(7, 0):
    msg.add(byte((bitLen shr (i * 8)) and 0xff'u64))

  var w: array[64, uint32]
  var offset = 0
  while offset < msg.len:
    for i in 0 ..< 16:
      let j = offset + i * 4
      w[i] = (uint32(msg[j]) shl 24) or (uint32(msg[j+1]) shl 16) or
             (uint32(msg[j+2]) shl 8) or uint32(msg[j+3])
    for i in 16 ..< 64:
      let s0 = rotr32(w[i-15], 7) xor rotr32(w[i-15], 18) xor (w[i-15] shr 3)
      let s1 = rotr32(w[i-2], 17) xor rotr32(w[i-2], 19) xor (w[i-2] shr 10)
      w[i] = w[i-16] + s0 + w[i-7] + s1

    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
    var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]

    for i in 0 ..< 64:
      let s1 = rotr32(e, 6) xor rotr32(e, 11) xor rotr32(e, 25)
      let ch = (e and f) xor ((not e) and g)
      let temp1 = hh + s1 + ch + sha256K[i] + w[i]
      let s0 = rotr32(a, 2) xor rotr32(a, 13) xor rotr32(a, 22)
      let maj = (a and b) xor (a and c) xor (b and c)
      let temp2 = s0 + maj
      hh = g; g = f; f = e; e = d + temp1
      d = c; c = b; b = a; a = temp1 + temp2

    h[0] += a; h[1] += b; h[2] += c; h[3] += d
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh
    offset += 64

  for i in 0 ..< 8:
    result[i*4]     = byte((h[i] shr 24) and 0xff'u32)
    result[i*4 + 1] = byte((h[i] shr 16) and 0xff'u32)
    result[i*4 + 2] = byte((h[i] shr 8) and 0xff'u32)
    result[i*4 + 3] = byte(h[i] and 0xff'u32)

proc formatHexColon*(bytes: openArray[byte]): string =
  result = newStringOfCap(bytes.len * 3)
  for i, b in bytes:
    if i > 0: result.add(':')
    result.add(toHex(b, 2))

# ---------------------------------------------------------------------------
# PEM encoding / decoding
# ---------------------------------------------------------------------------

proc encodePem*(label: string, der: openArray[byte]): string =
  var raw = newString(der.len)
  if der.len > 0:
    copyMem(addr raw[0], unsafeAddr der[0], der.len)
  let b64 = encode(raw)
  result = "-----BEGIN " & label & "-----\n"
  var i = 0
  while i < b64.len:
    let endIdx = min(i + 64, b64.len)
    result.add(b64[i ..< endIdx])
    result.add('\n')
    i = endIdx
  result.add("-----END " & label & "-----\n")

proc decodePemBlocks*(pemText: string): seq[PemBlock] =
  var inBlock = false
  var currentLabel = ""
  var b64Buf = ""
  for rawLine in pemText.splitLines():
    let line = rawLine.strip()
    if line.startsWith("-----BEGIN ") and line.endsWith("-----"):
      inBlock = true
      currentLabel = line[11 ..< line.len - 5].strip()
      b64Buf.setLen(0)
    elif inBlock and line.startsWith("-----END ") and line.endsWith("-----"):
      inBlock = false
      if b64Buf.len > 0:
        try:
          let decoded = decode(b64Buf)
          var bytes = newSeq[byte](decoded.len)
          if decoded.len > 0:
            copyMem(addr bytes[0], unsafeAddr decoded[0], decoded.len)
          result.add(PemBlock(label: currentLabel, data: bytes))
        except CatchableError:
          discard
      b64Buf.setLen(0)
    elif inBlock:
      b64Buf.add(line)

proc countPemCerts*(pemText: string): int =
  for line in pemText.splitLines():
    let s = line.strip()
    if s == "-----BEGIN CERTIFICATE-----" or s == "-----BEGIN TRUSTED CERTIFICATE-----":
      inc result

# ---------------------------------------------------------------------------
# ASN.1 DER Reader
# ---------------------------------------------------------------------------

type
  DerNode* = object
    tag*: byte
    contentStart*: int
    contentLen*: int
    nextPos*: int

proc readDerNode*(buf: openArray[byte], pos: int, limit: int): VaultResult[DerNode] =
  if pos >= limit:
    return err[DerNode](veCertificateInvalid, "Unexpected end of ASN.1 DER data")
  let tag = buf[pos]
  var idx = pos + 1
  if idx >= limit:
    return err[DerNode](veCertificateInvalid, "Truncated ASN.1 DER length")
  let firstLen = int(buf[idx])
  inc idx
  var contentLen = 0
  if (firstLen and 0x80) == 0:
    contentLen = firstLen
  else:
    let numOctets = firstLen and 0x7f
    if numOctets == 0 or numOctets > 4 or idx + numOctets > limit:
      return err[DerNode](veCertificateInvalid, "Invalid ASN.1 DER length encoding")
    for _ in 0 ..< numOctets:
      contentLen = (contentLen shl 8) or int(buf[idx])
      inc idx
  if contentLen < 0 or idx + contentLen > limit:
    return err[DerNode](veCertificateInvalid, "ASN.1 DER element exceeds buffer bounds")
  ok(DerNode(
    tag: tag,
    contentStart: idx,
    contentLen: contentLen,
    nextPos: idx + contentLen
  ))

proc decodeOid*(buf: openArray[byte], startPos, length: int): string =
  if length <= 0: return ""
  let first = int(buf[startPos])
  let arc1 = min(first div 40, 2)
  let arc2 = first - arc1 * 40
  var parts = @[$arc1, $arc2]
  var i = startPos + 1
  let endPos = startPos + length
  var val: uint64 = 0
  while i < endPos:
    let b = buf[i]
    val = (val shl 7) or uint64(b and 0x7f'u8)
    if (b and 0x80'u8) == 0:
      parts.add($val)
      val = 0
    inc i
  parts.join(".")

proc oidShortName(oid: string): string =
  case oid
  of "2.5.4.3": "CN"
  of "2.5.4.6": "C"
  of "2.5.4.7": "L"
  of "2.5.4.8": "ST"
  of "2.5.4.10": "O"
  of "2.5.4.11": "OU"
  of "1.2.840.113549.1.9.1": "emailAddress"
  else: oid

proc oidAlgorithmName(oid: string): string =
  case oid
  of "1.2.840.113549.1.1.1": "RSA"
  of "1.2.840.113549.1.1.5": "sha1WithRSAEncryption"
  of "1.2.840.113549.1.1.11": "sha256WithRSAEncryption"
  of "1.2.840.113549.1.1.12": "sha384WithRSAEncryption"
  of "1.2.840.113549.1.1.13": "sha512WithRSAEncryption"
  of "1.2.840.113549.1.1.10": "RSASSA-PSS"
  of "1.2.840.10045.2.1": "EC"
  of "1.2.840.10045.3.1.7": "P-256 (secp256r1)"
  of "1.3.132.0.34": "P-384 (secp384r1)"
  of "1.3.132.0.35": "P-521 (secp521r1)"
  of "1.2.840.10045.4.3.2": "ecdsa-with-SHA256"
  of "1.2.840.10045.4.3.3": "ecdsa-with-SHA384"
  of "1.2.840.10045.4.3.4": "ecdsa-with-SHA512"
  of "1.3.101.112": "Ed25519"
  else: oid

proc bytesToStr(buf: openArray[byte], startPos, length: int): string =
  result = newString(length)
  if length > 0:
    copyMem(addr result[0], unsafeAddr buf[startPos], length)

proc parseDistinguishedName(buf: openArray[byte], startPos, endPos: int): tuple[full: string, cn: string] =
  var parts: seq[string] = @[]
  var cn = ""
  var pos = startPos
  while pos < endPos:
    let setRes = readDerNode(buf, pos, endPos)
    if not setRes.isOk: break
    let setNode = setRes.val
    pos = setNode.nextPos
    var sp = setNode.contentStart
    let se = setNode.nextPos
    while sp < se:
      let seqRes = readDerNode(buf, sp, se)
      if not seqRes.isOk: break
      let seqNode = seqRes.val
      sp = seqNode.nextPos
      let oidRes = readDerNode(buf, seqNode.contentStart, seqNode.nextPos)
      if not oidRes.isOk: continue
      let valRes = readDerNode(buf, oidRes.val.nextPos, seqNode.nextPos)
      if not valRes.isOk: continue
      let oid = decodeOid(buf, oidRes.val.contentStart, oidRes.val.contentLen)
      let name = oidShortName(oid)
      let valStr = bytesToStr(buf, valRes.val.contentStart, valRes.val.contentLen)
      parts.add(name & "=" & valStr)
      if name == "CN" and cn.len == 0:
        cn = valStr
  (parts.join(", "), cn)

proc parseAsn1Time(buf: openArray[byte], node: DerNode): tuple[iso: string, epoch: int64] =
  let raw = bytesToStr(buf, node.contentStart, node.contentLen)
  try:
    var year, month, day, hour, minute, second: int
    if node.tag == 0x17'u8 and raw.len >= 12: # UTCTime YYMMDDHHMMSSZ
      let yy = parseInt(raw[0..1])
      year = if yy >= 50: 1900 + yy else: 2000 + yy
      month = parseInt(raw[2..3])
      day = parseInt(raw[4..5])
      hour = parseInt(raw[6..7])
      minute = parseInt(raw[8..9])
      second = parseInt(raw[10..11])
    elif node.tag == 0x18'u8 and raw.len >= 14: # GeneralizedTime YYYYMMDDHHMMSSZ
      year = parseInt(raw[0..3])
      month = parseInt(raw[4..5])
      day = parseInt(raw[6..7])
      hour = parseInt(raw[8..9])
      minute = parseInt(raw[10..11])
      second = parseInt(raw[12..13])
    else:
      return (raw, 0'i64)
    let dt = dateTime(year, Month(month), MonthdayRange(day),
                      HourRange(hour), MinuteRange(minute), SecondRange(second),
                      zone = utc())
    let iso = dt.format("yyyy-MM-dd HH:mm:ss") & " UTC"
    return (iso, dt.toTime.toUnix)
  except CatchableError:
    return (raw, 0'i64)

proc parseExtensions(buf: openArray[byte], startPos, endPos: int, info: var CertInfo) =
  let seqRes = readDerNode(buf, startPos, endPos)
  if not seqRes.isOk or seqRes.val.tag != 0x30'u8: return
  var pos = seqRes.val.contentStart
  let lim = seqRes.val.nextPos
  while pos < lim:
    let extRes = readDerNode(buf, pos, lim)
    if not extRes.isOk: break
    let extNode = extRes.val
    pos = extNode.nextPos
    let oidRes = readDerNode(buf, extNode.contentStart, extNode.nextPos)
    if not oidRes.isOk: continue
    let oid = decodeOid(buf, oidRes.val.contentStart, oidRes.val.contentLen)
    var cur = oidRes.val.nextPos
    let nextRes = readDerNode(buf, cur, extNode.nextPos)
    if not nextRes.isOk: continue
    var valNode = nextRes.val
    if valNode.tag == 0x01'u8: # optional critical BOOLEAN
      let octRes = readDerNode(buf, valNode.nextPos, extNode.nextPos)
      if not octRes.isOk: continue
      valNode = octRes.val
    if valNode.tag != 0x04'u8: continue # OCTET STRING

    if oid == "2.5.29.17": # subjectAltName
      let sanSeq = readDerNode(buf, valNode.contentStart, valNode.nextPos)
      if sanSeq.isOk and sanSeq.val.tag == 0x30'u8:
        var sp = sanSeq.val.contentStart
        let se = sanSeq.val.nextPos
        while sp < se:
          let itemRes = readDerNode(buf, sp, se)
          if not itemRes.isOk: break
          let item = itemRes.val
          sp = item.nextPos
          if item.tag == 0x82'u8: # dNSName [2]
            info.sanDnsNames.add(bytesToStr(buf, item.contentStart, item.contentLen))
          elif item.tag == 0x87'u8: # iPAddress [7]
            if item.contentLen == 4:
              info.sanIps.add(
                $buf[item.contentStart] & "." & $buf[item.contentStart+1] & "." &
                $buf[item.contentStart+2] & "." & $buf[item.contentStart+3]
              )
            elif item.contentLen == 16:
              var groups: seq[string] = @[]
              for g in 0 ..< 8:
                let hi = int(buf[item.contentStart + g*2])
                let lo = int(buf[item.contentStart + g*2 + 1])
                groups.add(toHex((hi shl 8) or lo, 4).toLowerAscii)
              info.sanIps.add(groups.join(":"))
    elif oid == "2.5.29.19": # basicConstraints
      let bcSeq = readDerNode(buf, valNode.contentStart, valNode.nextPos)
      if bcSeq.isOk and bcSeq.val.tag == 0x30'u8 and bcSeq.val.contentLen > 0:
        let caBool = readDerNode(buf, bcSeq.val.contentStart, bcSeq.val.nextPos)
        if caBool.isOk and caBool.val.tag == 0x01'u8 and caBool.val.contentLen == 1:
          info.isCA = buf[caBool.val.contentStart] != 0'u8

proc parseCertDer*(der: openArray[byte]): VaultResult[CertInfo] =
  ## Parses a DER-encoded X.509 certificate and extracts human-readable metadata.
  if der.len == 0:
    return err[CertInfo](veCertificateInvalid, "Empty certificate DER buffer")

  var info = CertInfo(version: 1, derLen: der.len)
  info.sha256Fingerprint = formatHexColon(sha256Digest(der))

  let certRes = readDerNode(der, 0, der.len)
  if not certRes.isOk or certRes.val.tag != 0x30'u8:
    return err[CertInfo](veCertificateInvalid, "Certificate is not a valid ASN.1 SEQUENCE")

  let tbsRes = readDerNode(der, certRes.val.contentStart, certRes.val.nextPos)
  if not tbsRes.isOk or tbsRes.val.tag != 0x30'u8:
    return err[CertInfo](veCertificateInvalid, "Certificate missing TBSCertificate SEQUENCE")

  var pos = tbsRes.val.contentStart
  let tbsEnd = tbsRes.val.nextPos

  # Optional [0] EXPLICIT version
  let firstRes = readDerNode(der, pos, tbsEnd)
  if not firstRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Truncated TBSCertificate")
  var serialNode: DerNode
  if firstRes.val.tag == 0xa0'u8:
    let verInt = readDerNode(der, firstRes.val.contentStart, firstRes.val.nextPos)
    if verInt.isOk and verInt.val.contentLen >= 1:
      info.version = int(der[verInt.val.contentStart]) + 1
    pos = firstRes.val.nextPos
    let serRes = readDerNode(der, pos, tbsEnd)
    if not serRes.isOk:
      return err[CertInfo](veCertificateInvalid, "Missing certificate serial number")
    serialNode = serRes.val
  else:
    serialNode = firstRes.val
  pos = serialNode.nextPos
  info.serialHex = formatHexColon(der[serialNode.contentStart ..< serialNode.nextPos])

  # Signature AlgorithmIdentifier
  let sigAlgRes = readDerNode(der, pos, tbsEnd)
  if not sigAlgRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Missing signature algorithm")
  pos = sigAlgRes.val.nextPos
  let sigOidRes = readDerNode(der, sigAlgRes.val.contentStart, sigAlgRes.val.nextPos)
  if sigOidRes.isOk and sigOidRes.val.tag == 0x06'u8:
    info.sigAlgorithm = oidAlgorithmName(decodeOid(der, sigOidRes.val.contentStart, sigOidRes.val.contentLen))

  # Issuer Name
  let issuerRes = readDerNode(der, pos, tbsEnd)
  if not issuerRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Missing certificate issuer")
  pos = issuerRes.val.nextPos
  let (issFull, issCN) = parseDistinguishedName(der, issuerRes.val.contentStart, issuerRes.val.nextPos)
  info.issuer = issFull
  info.issuerCN = issCN

  # Validity SEQUENCE
  let valRes = readDerNode(der, pos, tbsEnd)
  if not valRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Missing certificate validity")
  pos = valRes.val.nextPos
  let nbRes = readDerNode(der, valRes.val.contentStart, valRes.val.nextPos)
  if nbRes.isOk:
    let (iso, ep) = parseAsn1Time(der, nbRes.val)
    info.notBefore = iso
    info.notBeforeEpoch = ep
    let naRes = readDerNode(der, nbRes.val.nextPos, valRes.val.nextPos)
    if naRes.isOk:
      let (iso2, ep2) = parseAsn1Time(der, naRes.val)
      info.notAfter = iso2
      info.notAfterEpoch = ep2

  # Subject Name
  let subjRes = readDerNode(der, pos, tbsEnd)
  if not subjRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Missing certificate subject")
  pos = subjRes.val.nextPos
  let (subFull, subCN) = parseDistinguishedName(der, subjRes.val.contentStart, subjRes.val.nextPos)
  info.subject = subFull
  info.subjectCN = subCN

  # SubjectPublicKeyInfo
  let spkiRes = readDerNode(der, pos, tbsEnd)
  if not spkiRes.isOk:
    return err[CertInfo](veCertificateInvalid, "Missing SubjectPublicKeyInfo")
  pos = spkiRes.val.nextPos
  let algSeqRes = readDerNode(der, spkiRes.val.contentStart, spkiRes.val.nextPos)
  if algSeqRes.isOk and algSeqRes.val.tag == 0x30'u8:
    let kOidRes = readDerNode(der, algSeqRes.val.contentStart, algSeqRes.val.nextPos)
    if kOidRes.isOk and kOidRes.val.tag == 0x06'u8:
      let mainAlg = oidAlgorithmName(decodeOid(der, kOidRes.val.contentStart, kOidRes.val.contentLen))
      if kOidRes.val.nextPos < algSeqRes.val.nextPos:
        let paramRes = readDerNode(der, kOidRes.val.nextPos, algSeqRes.val.nextPos)
        if paramRes.isOk and paramRes.val.tag == 0x06'u8:
          let curveName = oidAlgorithmName(decodeOid(der, paramRes.val.contentStart, paramRes.val.contentLen))
          info.keyAlgorithm = mainAlg & " " & curveName
        else:
          info.keyAlgorithm = mainAlg
      else:
        info.keyAlgorithm = mainAlg

  # Optional tagged fields (extensions = [3] EXPLICIT = 0xa3)
  while pos < tbsEnd:
    let optRes = readDerNode(der, pos, tbsEnd)
    if not optRes.isOk: break
    pos = optRes.val.nextPos
    if optRes.val.tag == 0xa3'u8:
      parseExtensions(der, optRes.val.contentStart, optRes.val.nextPos, info)

  ok(info)

proc parseCertPem*(pemText: string): VaultResult[CertInfo] =
  let blocks = decodePemBlocks(pemText)
  for b in blocks:
    if b.label == "CERTIFICATE" or b.label == "TRUSTED CERTIFICATE":
      return parseCertDer(b.data)
  err[CertInfo](veCertificateInvalid, "No CERTIFICATE block found in PEM input")

# ---------------------------------------------------------------------------
# ASN.1 DER Writer helpers (used by keygen.nim for X.509 v3 certificates)
# ---------------------------------------------------------------------------

proc derEncodeLen*(length: int): seq[byte] =
  if length < 0x80:
    @[byte(length)]
  elif length <= 0xff:
    @[0x81'u8, byte(length)]
  elif length <= 0xffff:
    @[0x82'u8, byte((length shr 8) and 0xff), byte(length and 0xff)]
  else:
    @[0x83'u8, byte((length shr 16) and 0xff), byte((length shr 8) and 0xff), byte(length and 0xff)]

proc derWrap*(tag: byte, content: openArray[byte]): seq[byte] =
  let lenBytes = derEncodeLen(content.len)
  result = newSeqOfCap[byte](1 + lenBytes.len + content.len)
  result.add(tag)
  result.add(lenBytes)
  result.add(content)

proc derConcat*(parts: varargs[seq[byte]]): seq[byte] =
  var total = 0
  for p in parts: total += p.len
  result = newSeqOfCap[byte](total)
  for p in parts: result.add(p)

proc derSeq*(parts: varargs[seq[byte]]): seq[byte] =
  derWrap(0x30'u8, derConcat(parts))

proc derSet*(parts: varargs[seq[byte]]): seq[byte] =
  derWrap(0x31'u8, derConcat(parts))

proc derContext*(tagNum: byte, content: openArray[byte], constructed = true): seq[byte] =
  let tag = (if constructed: 0xa0'u8 else: 0x80'u8) or (tagNum and 0x1f'u8)
  derWrap(tag, content)

proc derInt*(rawUnsigned: openArray[byte]): seq[byte] =
  var i = 0
  while i < rawUnsigned.len - 1 and rawUnsigned[i] == 0'u8:
    inc i
  var body: seq[byte] = @[]
  if rawUnsigned.len == 0:
    body.add(0'u8)
  else:
    if (rawUnsigned[i] and 0x80'u8) != 0'u8:
      body.add(0'u8)
    for j in i ..< rawUnsigned.len:
      body.add(rawUnsigned[j])
  derWrap(0x02'u8, body)

proc derSmallInt*(v: int): seq[byte] =
  derInt(@[byte(v and 0xff)])

proc derBool*(v: bool): seq[byte] =
  derWrap(0x01'u8, @[if v: 0xff'u8 else: 0x00'u8])

proc derBitString*(bits: openArray[byte]): seq[byte] =
  var body = newSeqOfCap[byte](bits.len + 1)
  body.add(0'u8) # 0 unused bits
  body.add(bits)
  derWrap(0x03'u8, body)

proc derOctetString*(data: openArray[byte]): seq[byte] =
  derWrap(0x04'u8, data)

proc derOid*(oidStr: string): seq[byte] =
  let parts = oidStr.split('.')
  var body: seq[byte] = @[]
  if parts.len >= 2:
    body.add(byte(parseInt(parts[0]) * 40 + parseInt(parts[1])))
    for i in 2 ..< parts.len:
      var v = parseBiggestUInt(parts[i])
      var enc: seq[byte] = @[byte(v and 0x7f'u64)]
      v = v shr 7
      while v > 0'u64:
        enc.add(byte((v and 0x7f'u64) or 0x80'u64))
        v = v shr 7
      for j in countdown(enc.len - 1, 0):
        body.add(enc[j])
  derWrap(0x06'u8, body)

proc derStr*(tag: byte, s: string): seq[byte] =
  var bytes = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr bytes[0], unsafeAddr s[0], s.len)
  derWrap(tag, bytes)

proc derUtf8String*(s: string): seq[byte] =
  derStr(0x0c'u8, s)

proc derUtcTime*(t: DateTime): seq[byte] =
  let u = t.utc
  if u.year >= 1950 and u.year <= 2049:
    derStr(0x17'u8, u.format("yyMMddHHmmss") & "Z")
  else:
    derStr(0x18'u8, u.format("yyyyMMddHHmmss") & "Z")
