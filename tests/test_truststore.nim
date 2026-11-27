import std/[unittest, os]
import ../src/nimvault/[errors, truststore]

const vendorCaPath = currentSourcePath.parentDir.parentDir / "src" / "nimvault" / "vendor" / "cacert.pem"

suite "Tiered Trust Store Resolution":
  test "Explicit CA bundle file loads Mozilla cacert.pem":
    let res = resolveTrustStore(explicitPath = vendorCaPath)
    check res.isOk
    check res.val.sourceKind == tsExplicitFile
    check res.val.certCount >= 100
    check res.val.pemData.len > 100_000

  test "Missing explicit CA file fails strictly without silent fallback":
    let res = resolveTrustStore(explicitPath = "nonexistent_ca_bundle_12345.pem")
    check res.isErr
    check res.err.kind == veTrustStoreNotFound

  test "SSL_CERT_FILE environment variable takes priority over OS and embedded":
    let prev = getEnv("SSL_CERT_FILE")
    putEnv("SSL_CERT_FILE", vendorCaPath)
    defer:
      if prev.len > 0: putEnv("SSL_CERT_FILE", prev)
      else: delEnv("SSL_CERT_FILE")

    let res = resolveTrustStore()
    check res.isOk
    check res.val.sourceKind == tsEnvVar
    check res.val.sourcePath == vendorCaPath
    check res.val.certCount >= 100

  test "Compile-time embedded roots flag behaves as expected":
    when defined(nimvaultEmbedRoots):
      check hasEmbeddedRoots()
      let emb = loadEmbeddedTrustStore()
      check emb.isOk
      check emb.val.sourceKind == tsEmbeddedRoots
      check emb.val.sourcePath == "embedded:mozilla-ca-bundle"
      check emb.val.certCount >= 100
    else:
      check not hasEmbeddedRoots()
      let emb = loadEmbeddedTrustStore()
      check emb.isErr
      check emb.err.kind == veTrustStoreNotFound

  test "Default resolveTrustStore succeeds when OS or embedded roots exist":
    let prev = getEnv("SSL_CERT_FILE")
    delEnv("SSL_CERT_FILE")
    defer:
      if prev.len > 0: putEnv("SSL_CERT_FILE", prev)

    let res = resolveTrustStore()
    when defined(nimvaultEmbedRoots):
      check res.isOk
      check res.val.certCount > 0
      check res.val.sourceKind in {tsSystemStore, tsEmbeddedRoots}
    else:
      if res.isOk:
        check res.val.certCount > 0
        check res.val.sourceKind == tsSystemStore
      else:
        check res.err.kind == veTrustStoreNotFound
