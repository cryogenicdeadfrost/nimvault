## Actionable TLS error types, Result container, and BearSSL/RFC 5246 diagnostics.

import std/strutils

type
  VaultErrorKind* = enum
    veNone
    veTrustStoreNotFound
    veTrustStoreInvalid
    veHandshakeFailed
    veCertificateExpired
    veCertificateUntrusted
    veHostnameMismatch
    veCertificateInvalid
    veProtocolVersionUnsupported
    veCipherSuiteMismatch
    veAlpnMismatch
    veTlsAlertReceived
    veTlsAlertSent
    veIoError
    veConnectionClosed
    veInvalidConfig
    veKeygenFailed
    veInternalError

  VaultError* = object
    kind*: VaultErrorKind
    code*: int           ## Raw backend error code (e.g. BearSSL BR_ERR_*), 0 if N/A
    alertCode*: int      ## TLS alert code (0..255), or -1 if not a TLS alert
    message*: string
    likelyCause*: string
    suggestion*: string

  VaultResult*[T] = object
    case isOk*: bool
    of true:
      val*: T
    of false:
      err*: VaultError

proc ok*[T](value: T): VaultResult[T] {.inline.} =
  VaultResult[T](isOk: true, val: value)

proc err*[T](e: VaultError): VaultResult[T] {.inline.} =
  VaultResult[T](isOk: false, err: e)

proc err*[T](kind: VaultErrorKind, message: string,
             likelyCause = "", suggestion = "",
             code = 0, alertCode = -1): VaultResult[T] {.inline.} =
  VaultResult[T](
    isOk: false,
    err: VaultError(
      kind: kind,
      code: code,
      alertCode: alertCode,
      message: message,
      likelyCause: likelyCause,
      suggestion: suggestion
    )
  )

proc isErr*[T](r: VaultResult[T]): bool {.inline.} =
  not r.isOk

proc get*[T](r: VaultResult[T]): T {.inline.} =
  if not r.isOk:
    raise newException(ValueError, "VaultResult error: " & r.err.message)
  r.val

proc getOrElse*[T](r: VaultResult[T], fallback: T): T {.inline.} =
  if r.isOk: r.val else: fallback

proc `$`*(e: VaultError): string =
  result = e.message
  if e.likelyCause.len > 0:
    result.add(" | Cause: " & e.likelyCause)
  if e.suggestion.len > 0:
    result.add(" | Fix: " & e.suggestion)

proc formatDiagnostic*(e: VaultError): string =
  ## Human-friendly multi-line diagnostic string for CLI and logs.
  var lines: seq[string] = @[]
  lines.add("Error [" & $e.kind & "]: " & e.message)
  if e.code != 0:
    var meta = "  Backend Code: " & $e.code
    if e.alertCode >= 0:
      meta.add(" (TLS alert " & $e.alertCode & ")")
    lines.add(meta)
  if e.likelyCause.len > 0:
    lines.add("  Likely Cause: " & e.likelyCause)
  if e.suggestion.len > 0:
    lines.add("  Suggestion:   " & e.suggestion)
  lines.join("\n")

proc tlsAlertName*(alertCode: int): string =
  case alertCode
  of 0: "close_notify"
  of 10: "unexpected_message"
  of 20: "bad_record_mac"
  of 21: "decryption_failed"
  of 22: "record_overflow"
  of 30: "decompression_failure"
  of 40: "handshake_failure"
  of 41: "no_certificate"
  of 42: "bad_certificate"
  of 43: "unsupported_certificate"
  of 44: "certificate_revoked"
  of 45: "certificate_expired"
  of 46: "certificate_unknown"
  of 47: "illegal_parameter"
  of 48: "unknown_ca"
  of 49: "access_denied"
  of 50: "decode_error"
  of 51: "decrypt_error"
  of 70: "protocol_version"
  of 71: "insufficient_security"
  of 80: "internal_error"
  of 86: "inappropriate_fallback"
  of 90: "user_canceled"
  of 100: "no_renegotiation"
  of 109: "missing_extension"
  of 110: "unsupported_extension"
  of 112: "unrecognized_name"
  of 113: "bad_certificate_status_response"
  of 115: "unknown_psk_identity"
  of 116: "certificate_required"
  of 120: "no_application_protocol"
  else: "unknown_alert(" & $alertCode & ")"

proc diagnoseTlsAlert*(alertCode: int, received: bool, serverName = ""): VaultError =
  let name = tlsAlertName(alertCode)
  let dir = if received: "received from peer" else: "sent to peer"
  let baseCode = if received: 256 + alertCode else: 512 + alertCode
  let defaultKind = if received: veTlsAlertReceived else: veTlsAlertSent

  case alertCode
  of 0:
    VaultError(
      kind: veConnectionClosed,
      code: baseCode,
      alertCode: alertCode,
      message: "TLS close_notify " & dir,
      likelyCause: "Peer initiated a graceful TLS shutdown.",
      suggestion: "Close the underlying socket cleanly."
    )
  of 40:
    VaultError(
      kind: veHandshakeFailed,
      code: baseCode,
      alertCode: alertCode,
      message: "Server rejected handshake (TLS alert 40: handshake_failure)",
      likelyCause: "SNI hostname mismatch, TLS 1.2 disabled on server (TLS 1.3-only endpoint), or no mutually supported cipher suites.",
      suggestion: "Verify the SNI hostname" & (if serverName.len > 0: " ('" & serverName & "')" else: "") &
                  " and check whether the server permits TLS 1.2 (BearSSL supports TLS 1.0-1.2)."
    )
  of 42, 43, 46:
    VaultError(
      kind: veCertificateInvalid,
      code: baseCode,
      alertCode: alertCode,
      message: "Certificate rejected (TLS alert " & $alertCode & ": " & name & ")",
      likelyCause: "The peer certificate failed format, policy, or chain checks.",
      suggestion: "Inspect the server certificate with `nimvault probe --insecure <host>`."
    )
  of 45:
    VaultError(
      kind: veCertificateExpired,
      code: baseCode,
      alertCode: alertCode,
      message: "Certificate expired (TLS alert 45: certificate_expired)",
      likelyCause: "The certificate validity period has expired or the system clock is skewed.",
      suggestion: "Check system UTC time or renew the server certificate."
    )
  of 48:
    VaultError(
      kind: veCertificateUntrusted,
      code: baseCode,
      alertCode: alertCode,
      message: "Unknown certificate authority (TLS alert 48: unknown_ca)",
      likelyCause: "The peer does not trust the presented certificate chain or CA root.",
      suggestion: "Provide the custom CA bundle via SSL_CERT_FILE or `--ca-file`."
    )
  of 70:
    VaultError(
      kind: veProtocolVersionUnsupported,
      code: baseCode,
      alertCode: alertCode,
      message: "Protocol version rejected (TLS alert 70: protocol_version)",
      likelyCause: "The peer requires a TLS version outside the configured range (for example, a TLS 1.3-only server).",
      suggestion: "BearSSL supports TLS 1.0-1.2; ensure the endpoint enables TLS 1.2 or check min/max version settings."
    )
  of 71:
    VaultError(
      kind: veCipherSuiteMismatch,
      code: baseCode,
      alertCode: alertCode,
      message: "Insufficient security (TLS alert 71: insufficient_security)",
      likelyCause: "Server security policy rejected the offered TLS version or cipher suites.",
      suggestion: "Ensure TLS 1.2 with AEAD cipher suites (ECDHE+AES-GCM/ChaCha20) is permitted."
    )
  of 80:
    VaultError(
      kind: defaultKind,
      code: baseCode,
      alertCode: alertCode,
      message: "Peer reported internal TLS error (TLS alert 80: internal_error)",
      likelyCause: "Misconfigured server/proxy, missing backend certificate, or transient server fault.",
      suggestion: "Retry or check reverse proxy / TLS termination logs on the server."
    )
  of 112:
    VaultError(
      kind: veHostnameMismatch,
      code: baseCode,
      alertCode: alertCode,
      message: "Server rejected SNI hostname (TLS alert 112: unrecognized_name)",
      likelyCause: "The SNI hostname" & (if serverName.len > 0: " '" & serverName & "'" else: "") &
                   " is not recognized by the server's virtual host configuration.",
      suggestion: "Pass the correct domain name in `serverName` / `--sni`."
    )
  of 120:
    VaultError(
      kind: veAlpnMismatch,
      code: baseCode,
      alertCode: alertCode,
      message: "ALPN protocol negotiation failed (TLS alert 120: no_application_protocol)",
      likelyCause: "None of the client's offered ALPN protocols are supported by the server.",
      suggestion: "Adjust offered ALPN protocols (e.g. 'http/1.1') or omit ALPN."
    )
  else:
    VaultError(
      kind: defaultKind,
      code: baseCode,
      alertCode: alertCode,
      message: "Fatal TLS alert " & $alertCode & " (" & name & ") " & dir,
      likelyCause: "Peer terminated the TLS session with alert '" & name & "'.",
      suggestion: "Inspect peer configuration or run `nimvault probe` with `--insecure` to inspect the handshake."
    )

proc diagnoseBearSslError*(brErr: int, serverName = ""): VaultError =
  ## Maps raw BearSSL error codes (BR_ERR_*, BR_ERR_X509_*, and fatal alerts)
  ## into actionable human-readable VaultError diagnostics.
  if brErr == 0:
    return VaultError(kind: veNone, code: 0, alertCode: -1, message: "No error")

  if brErr >= 256 and brErr < 512:
    return diagnoseTlsAlert(brErr - 256, received = true, serverName = serverName)
  if brErr >= 512 and brErr < 768:
    return diagnoseTlsAlert(brErr - 512, received = false, serverName = serverName)

  case brErr
  of 1:
    VaultError(kind: veInvalidConfig, code: brErr, alertCode: -1,
      message: "Invalid TLS engine parameter (BR_ERR_BAD_PARAM)",
      likelyCause: "An invalid configuration option or null buffer was supplied.",
      suggestion: "Check TlsConfig parameters (versions, SNI, ALPN, certificates).")
  of 2:
    VaultError(kind: veInternalError, code: brErr, alertCode: -1,
      message: "Invalid TLS engine state transition (BR_ERR_BAD_STATE)",
      likelyCause: "Engine operation called out of order.",
      suggestion: "Drive I/O strictly according to `nextAction()`.")
  of 3, 4:
    VaultError(kind: veProtocolVersionUnsupported, code: brErr, alertCode: -1,
      message: "Unsupported or mismatched TLS protocol version (BR_ERR_" &
               (if brErr == 3: "UNSUPPORTED_VERSION" else: "BAD_VERSION") & ")",
      likelyCause: "Peer responded with an unsupported TLS version or plaintext HTTP instead of TLS.",
      suggestion: "Confirm you are connecting to a TLS port (e.g. 443) and that TLS 1.2 is enabled.")
  of 5, 6:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "Invalid or oversized TLS record (code " & $brErr & ")",
      likelyCause: "Peer may be speaking plaintext HTTP/non-TLS on this port, or sent a record exceeding TLS limits.",
      suggestion: "Verify the target host and port speak TLS.")
  of 7:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "Record decryption or MAC verification failed (BR_ERR_BAD_MAC)",
      likelyCause: "Corrupted network stream, middlebox tampering, or mismatched cipher state.",
      suggestion: "Check for intercepting proxies or packet corruption.")
  of 8:
    VaultError(kind: veInternalError, code: brErr, alertCode: -1,
      message: "No cryptographic entropy available (BR_ERR_NO_RANDOM)",
      likelyCause: "Operating system CSPRNG seeding failed.",
      suggestion: "Ensure OS entropy source (/dev/urandom or Windows CryptoAPI) is accessible.")
  of 9, 10, 12, 13, 14:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "Malformed or unexpected TLS handshake message (code " & $brErr & ")",
      likelyCause: "Peer may not be a TLS server (e.g. HTTP plaintext on port 80) or middlebox corrupted the handshake.",
      suggestion: "Verify the port uses TLS and check firewall/proxy rules.")
  of 16:
    VaultError(kind: veCipherSuiteMismatch, code: brErr, alertCode: -1,
      message: "Incompatible cipher suite selected (BR_ERR_BAD_CIPHER_SUITE)",
      likelyCause: "Server chose a cipher suite not offered or supported by the client.",
      suggestion: "Verify server cipher suite configuration.")
  of 21:
    VaultError(kind: veHostnameMismatch, code: brErr, alertCode: -1,
      message: "Invalid SNI extension (BR_ERR_BAD_SNI)",
      likelyCause: "Malformed Server Name Indication hostname.",
      suggestion: "Provide a valid DNS hostname without scheme or port.")
  of 23:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "Cryptographic limit exceeded (BR_ERR_LIMIT_EXCEEDED)",
      likelyCause: "Peer's certificate key (e.g. >4096-bit RSA) or handshake exceeded engine limits.",
      suggestion: "Inspect peer certificate key parameters.")
  of 26, 27:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "Unsupported algorithm or invalid handshake signature (code " & $brErr & ")",
      likelyCause: "Server used an unsupported elliptic curve/signature algorithm (e.g. Ed25519-only) or invalid signature.",
      suggestion: "BearSSL supports RSA (PKCS#1 v1.5) and ECDSA (P-256/P-384/P-521) with ECDHE/X25519.")
  of 31:
    VaultError(kind: veIoError, code: brErr, alertCode: -1,
      message: "Underlying transport I/O error or premature EOF (BR_ERR_IO)",
      likelyCause: "TCP connection was reset or closed mid-handshake (firewall, idle timeout, or port mismatch).",
      suggestion: "Check network reachability and firewall rules.")
  of 33..51:
    VaultError(kind: veCertificateInvalid, code: brErr, alertCode: -1,
      message: "Peer X.509 certificate decoding/structure error (BR_ERR_X509 code " & $brErr & ")",
      likelyCause: "Certificate chain is empty, truncated, malformed ASN.1, or uses an unsupported key/extension.",
      suggestion: "Inspect the server certificate chain with `nimvault probe --insecure`.")
  of 52:
    VaultError(kind: veCertificateInvalid, code: brErr, alertCode: -1,
      message: "Invalid certificate signature in chain (BR_ERR_X509_BAD_SIGNATURE)",
      likelyCause: "A certificate in the server's chain failed cryptographic signature verification.",
      suggestion: "Verify the server's fullchain certificate bundle is properly ordered and uncorrupted.")
  of 53:
    VaultError(kind: veCertificateExpired, code: brErr, alertCode: -1,
      message: "Certificate validation time unknown (BR_ERR_X509_TIME_UNKNOWN)",
      likelyCause: "System clock was not available during certificate validity check.",
      suggestion: "Ensure system clock is properly set.")
  of 54:
    VaultError(kind: veCertificateExpired, code: brErr, alertCode: -1,
      message: "Peer certificate is expired or not yet valid (BR_ERR_X509_EXPIRED)",
      likelyCause: "The current UTC date falls outside the certificate's NotBefore..NotAfter window.",
      suggestion: "Check your system clock or renew the server's TLS certificate.")
  of 55:
    VaultError(kind: veCertificateUntrusted, code: brErr, alertCode: -1,
      message: "Certificate chain Issuer/Subject DN mismatch (BR_ERR_X509_DN_MISMATCH)",
      likelyCause: "Server sent certificates out of order or missing an intermediate CA certificate.",
      suggestion: "Ensure the server sends the complete leaf + intermediate certificate chain.")
  of 56:
    let target = if serverName.len > 0: " for '" & serverName & "'" else: ""
    let targetParen = if serverName.len > 0: " ('" & serverName & "')" else: ""
    VaultError(kind: veHostnameMismatch, code: brErr, alertCode: -1,
      message: "Certificate hostname mismatch" & target & " (BR_ERR_X509_BAD_SERVER_NAME)",
      likelyCause: "The server's certificate SAN (dNSName) and CN do not match the requested hostname" & targetParen & ".",
      suggestion: "Connect using a hostname listed in the certificate's SANs, or pass the matching `--sni` name.")
  of 57, 58, 59, 60:
    VaultError(kind: veCertificateInvalid, code: brErr, alertCode: -1,
      message: "Certificate constraint or key usage violation (BR_ERR_X509 code " & $brErr & ")",
      likelyCause: "Certificate failed BasicConstraints (not a CA), KeyUsage, unknown critical extension, or weak key (<1024-bit RSA) checks.",
      suggestion: "Inspect the server certificate extensions with `nimvault probe --insecure`.")
  of 62:
    VaultError(kind: veCertificateUntrusted, code: brErr, alertCode: -1,
      message: "Certificate chain not trusted (BR_ERR_X509_NOT_TRUSTED)",
      likelyCause: "The server's certificate is self-signed, issued by a private/corporate CA, or missing an intermediate certificate.",
      suggestion: "Add the issuing CA via `SSL_CERT_FILE` / `--ca-file`, compile with `-d:nimvaultEmbedRoots`, or verify server sends fullchain.")
  else:
    VaultError(kind: veHandshakeFailed, code: brErr, alertCode: -1,
      message: "TLS engine error (BearSSL code " & $brErr & ")",
      likelyCause: "Unhandled TLS protocol or verification error.",
      suggestion: "Inspect connection details with `nimvault probe --insecure`.")
