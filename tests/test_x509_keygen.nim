import std/[unittest, os, strutils]
import ../src/nimtls/[x509, keygen]

const vendorCaPath = currentSourcePath.parentDir.parentDir / "src" / "nimtls" / "vendor" / "cacert.pem"

suite "X.509 ASN.1 Parser & ECDSA P-256 Keygen":
  test "Generate self-signed ECDSA P-256 keypair and X.509 v3 certificate":
    var opts = defaultKeygenOptions("test.nimtls.local")
    opts.organization = "NimTLS Test Org"
    opts.sanDnsNames = @["test.nimtls.local", "localhost"]
    opts.validDays = 90

    let res = generateSelfSignedEcP256(opts)
    check res.isOk
    let bundle = res.val

    check "-----BEGIN PRIVATE KEY-----" in bundle.privateKeyPem
    check "-----END PRIVATE KEY-----" in bundle.privateKeyPem
    check "-----BEGIN CERTIFICATE-----" in bundle.certificatePem
    check "-----END CERTIFICATE-----" in bundle.certificatePem

    let parsed = parseCertPem(bundle.certificatePem)
    check parsed.isOk
    let info = parsed.val
    check info.version == 3
    check info.subjectCN == "test.nimtls.local"
    check info.issuerCN == "test.nimtls.local"
    check "NimTLS Test Org" in info.subject
    check info.sanDnsNames == @["test.nimtls.local", "localhost"]
    check info.isCA
    check "P-256" in info.keyAlgorithm
    check info.sigAlgorithm == "ecdsa-with-SHA256"
    check info.sha256Fingerprint.len == 95 # 32 hex bytes + 31 colons
    check info.notAfterEpoch > info.notBeforeEpoch

  test "Pure Nim X.509 parser parses real Mozilla CA certificates from vendor/cacert.pem":
    let pem = readFile(vendorCaPath)
    let blocks = decodePemBlocks(pem)
    check blocks.len >= 100

    var parsedCount = 0
    for i in 0 ..< min(25, blocks.len):
      let c = parseCertDer(blocks[i].data)
      check c.isOk
      check c.val.subject.len > 0
      check c.val.issuer.len > 0
      check c.val.sha256Fingerprint.len == 95
      inc parsedCount
    check parsedCount == 25
