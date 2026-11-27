import std/[unittest, strutils]
import ../src/nimtls/errors

suite "TlsResult & Actionable TLS Diagnostics":
  test "TlsResult ok/err helpers":
    let a = ok(42)
    check a.isOk
    check not a.isErr
    check a.get == 42
    check a.getOrElse(0) == 42

    let b = err[int](teInvalidConfig, "bad config", likelyCause = "test", suggestion = "fix it")
    check b.isErr
    check not b.isOk
    check b.getOrElse(99) == 99
    check b.err.kind == teInvalidConfig
    check "bad config" in formatDiagnostic(b.err)
    check "fix it" in formatDiagnostic(b.err)

  test "TLS received fatal alerts map to actionable diagnostics":
    let hs = diagnoseBearSslError(256 + 40, "api.example.com")
    check hs.kind == teHandshakeFailed
    check hs.alertCode == 40
    check "handshake_failure" in hs.message
    check "SNI" in hs.likelyCause
    check "api.example.com" in hs.suggestion

    let sni = diagnoseBearSslError(256 + 112, "wrong.example.com")
    check sni.kind == teHostnameMismatch
    check sni.alertCode == 112
    check "unrecognized_name" in sni.message
    check "wrong.example.com" in sni.likelyCause

    let ver = diagnoseBearSslError(256 + 70)
    check ver.kind == teProtocolVersionUnsupported
    check ver.alertCode == 70
    check "TLS 1.3" in ver.likelyCause

    let alpn = diagnoseBearSslError(256 + 120)
    check alpn.kind == teAlpnMismatch
    check alpn.alertCode == 120
    check "ALPN" in alpn.message

  test "BearSSL X.509 error codes map to actionable diagnostics":
    let expired = diagnoseBearSslError(54)
    check expired.kind == teCertificateExpired
    check "expired" in expired.message.toLowerAscii

    let badHost = diagnoseBearSslError(56, "github.com")
    check badHost.kind == teHostnameMismatch
    check "github.com" in badHost.message

    let untrusted = diagnoseBearSslError(62)
    check untrusted.kind == teCertificateUntrusted
    check "nimtlsEmbedRoots" in untrusted.suggestion

    let ioErr = diagnoseBearSslError(31)
    check ioErr.kind == teIoError
