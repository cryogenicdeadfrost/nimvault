import std/[unittest, strutils]
import ../src/nimvault/errors

suite "VaultResult & Actionable TLS Diagnostics":
  test "VaultResult ok/err helpers":
    let a = ok(42)
    check a.isOk
    check not a.isErr
    check a.get == 42
    check a.getOrElse(0) == 42

    let b = err[int](veInvalidConfig, "bad config", likelyCause = "test", suggestion = "fix it")
    check b.isErr
    check not b.isOk
    check b.getOrElse(99) == 99
    check b.err.kind == veInvalidConfig
    check "bad config" in formatDiagnostic(b.err)
    check "fix it" in formatDiagnostic(b.err)

  test "TLS received fatal alerts map to actionable diagnostics":
    let hs = diagnoseBearSslError(256 + 40, "api.example.com")
    check hs.kind == veHandshakeFailed
    check hs.alertCode == 40
    check "handshake_failure" in hs.message
    check "SNI" in hs.likelyCause
    check "api.example.com" in hs.suggestion

    let sni = diagnoseBearSslError(256 + 112, "wrong.example.com")
    check sni.kind == veHostnameMismatch
    check sni.alertCode == 112
    check "unrecognized_name" in sni.message
    check "wrong.example.com" in sni.likelyCause

    let ver = diagnoseBearSslError(256 + 70)
    check ver.kind == veProtocolVersionUnsupported
    check ver.alertCode == 70
    check "TLS 1.3" in ver.likelyCause

    let alpn = diagnoseBearSslError(256 + 120)
    check alpn.kind == veAlpnMismatch
    check alpn.alertCode == 120
    check "ALPN" in alpn.message

  test "BearSSL X.509 error codes map to actionable diagnostics":
    let expired = diagnoseBearSslError(54)
    check expired.kind == veCertificateExpired
    check "expired" in expired.message.toLowerAscii

    let badHost = diagnoseBearSslError(56, "github.com")
    check badHost.kind == veHostnameMismatch
    check "github.com" in badHost.message

    let untrusted = diagnoseBearSslError(62)
    check untrusted.kind == veCertificateUntrusted
    check "nimvaultEmbedRoots" in untrusted.suggestion

    let ioErr = diagnoseBearSslError(31)
    check ioErr.kind == veIoError
