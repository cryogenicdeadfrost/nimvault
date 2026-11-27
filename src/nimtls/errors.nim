# Error types, Result wrapper, and BearSSL/RFC 5246 code translators.

import std/strutils

type
  TlsErrorKind* = enum
    teNone
    teTrustStoreNotFound
    teTrustStoreInvalid
    teHandshakeFailed
    teCertificateExpired
    teCertificateUntrusted
    teHostnameMismatch
    teCertificateInvalid
    teProtocolVersionUnsupported
    teCipherSuiteMismatch
    teAlpnMismatch
    teTlsAlertReceived
    teTlsAlertSent
    teIoError
    teConnectionClosed
    teInvalidConfig
    teKeygenFailed
    teInternalError

  TlsError* = object
    kind*: TlsErrorKind
    code*: int        # BearSSL BR_ERR_* code (0 if not from BearSSL)
    alertCode*: int   # RFC 5246 alert id (0..255), -1 if not an alert
    message*: string
    likelyCause*: string
    suggestion*: string

  TlsResult*[T] = object
    case isOk*: bool
    of true:
      val*: T
    of false:
      err*: TlsError

proc ok*[T](value: T): TlsResult[T] {.inline.} =
  TlsResult[T](isOk: true, val: value)

proc err*[T](e: TlsError): TlsResult[T] {.inline.} =
  TlsResult[T](isOk: false, err: e)

proc err*[T](kind: TlsErrorKind, message: string,
             likelyCause = "", suggestion = "",
             code = 0, alertCode = -1): TlsResult[T] {.inline.} =
  TlsResult[T](
    isOk: false,
    err: TlsError(
      kind: kind,
      code: code,
      alertCode: alertCode,
      message: message,
      likelyCause: likelyCause,
      suggestion: suggestion
    )
  )

proc isErr*[T](r: TlsResult[T]): bool {.inline.} = not r.isOk

proc get*[T](r: TlsResult[T]): T {.inline.} =
  if not r.isOk:
    raise newException(ValueError, "TlsResult error: " & r.err.message)
  r.val

proc getOrElse*[T](r: TlsResult[T], fallback: T): T {.inline.} =
  if r.isOk: r.val else: fallback

proc `$`*(e: TlsError): string =
  result = e.message
  if e.likelyCause.len > 0: result.add(" | Cause: " & e.likelyCause)
  if e.suggestion.len > 0: result.add(" | Fix: " & e.suggestion)

proc prettyErr*(e: TlsError): string =
  var lines = @["Error [" & $e.kind & "]: " & e.message]
  if e.code != 0:
    var meta = "  Backend Code: " & $e.code
    if e.alertCode >= 0: meta.add(" (TLS alert " & $e.alertCode & ")")
    lines.add(meta)
  if e.likelyCause.len > 0: lines.add("  Likely Cause: " & e.likelyCause)
  if e.suggestion.len > 0: lines.add("  Suggestion:   " & e.suggestion)
  lines.join("\n")

proc formatDiagnostic*(e: TlsError): string {.inline.} = prettyErr(e)

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

proc explainAlert(alertCode: int, received: bool, serverName = ""): TlsError =
  let name = tlsAlertName(alertCode)
  let dir = if received: "received from peer" else: "sent to peer"
  let baseCode = if received: 256 + alertCode else: 512 + alertCode
  let defaultKind = if received: teTlsAlertReceived else: teTlsAlertSent

  case alertCode
  of 0:
    TlsError(kind: teConnectionClosed, code: baseCode, alertCode: alertCode,
      message: "TLS close_notify " & dir,
      likelyCause: "Peer initiated a graceful TLS shutdown.",
      suggestion: "Close the socket cleanly.")
  of 40:
    TlsError(kind: teHandshakeFailed, code: baseCode, alertCode: alertCode,
      message: "Server rejected handshake (TLS alert 40: handshake_failure)",
      likelyCause: "SNI mismatch, server disabled TLS 1.2 (TLS 1.3-only), or no overlapping cipher suites.",
      suggestion: "Check SNI" & (if serverName.len > 0: " ('" & serverName & "')" else: "") &
                  " and make sure the server accepts TLS 1.2 (BearSSL stops at TLS 1.2).")
  of 42, 43, 46:
    TlsError(kind: teCertificateInvalid, code: baseCode, alertCode: alertCode,
      message: "Certificate rejected (TLS alert " & $alertCode & ": " & name & ")",
      likelyCause: "Peer cert failed format, policy, or chain checks.",
      suggestion: "Run `nimtls probe --insecure <host>` to see what cert the server actually sent.")
  of 45:
    TlsError(kind: teCertificateExpired, code: baseCode, alertCode: alertCode,
      message: "Certificate expired (TLS alert 45: certificate_expired)",
      likelyCause: "Cert validity window passed or local clock is way off.",
      suggestion: "Check UTC clock or renew the cert.")
  of 48:
    TlsError(kind: teCertificateUntrusted, code: baseCode, alertCode: alertCode,
      message: "Unknown CA (TLS alert 48: unknown_ca)",
      likelyCause: "Peer doesn't trust the cert chain or issuing CA.",
      suggestion: "Pass the custom CA via SSL_CERT_FILE or `--ca-file`.")
  of 70:
    TlsError(kind: teProtocolVersionUnsupported, code: baseCode, alertCode: alertCode,
      message: "Protocol version rejected (TLS alert 70: protocol_version)",
      likelyCause: "Server probably demands TLS 1.3 only, or min/max TLS version doesn't overlap.",
      suggestion: "BearSSL supports TLS 1.0-1.2; verify the endpoint permits TLS 1.2.")
  of 71:
    TlsError(kind: teCipherSuiteMismatch, code: baseCode, alertCode: alertCode,
      message: "Insufficient security (TLS alert 71: insufficient_security)",
      likelyCause: "Server policy rejected offered TLS version or cipher suites.",
      suggestion: "Check that TLS 1.2 AEAD suites (ECDHE+AES-GCM/ChaCha20) are allowed.")
  of 80:
    TlsError(kind: defaultKind, code: baseCode, alertCode: alertCode,
      message: "Peer reported internal TLS error (TLS alert 80: internal_error)",
      likelyCause: "Server/proxy hiccup or missing backend cert.",
      suggestion: "Retry or check reverse proxy logs.")
  of 112:
    TlsError(kind: teHostnameMismatch, code: baseCode, alertCode: alertCode,
      message: "Server rejected SNI hostname (TLS alert 112: unrecognized_name)",
      likelyCause: "SNI" & (if serverName.len > 0: " '" & serverName & "'" else: "") &
                   " isn't configured on this server's vhosts.",
      suggestion: "Pass the real domain in `serverName` / `--sni`.")
  of 120:
    TlsError(kind: teAlpnMismatch, code: baseCode, alertCode: alertCode,
      message: "ALPN negotiation failed (TLS alert 120: no_application_protocol)",
      likelyCause: "Server doesn't speak any of the offered ALPN protocols.",
      suggestion: "Offer 'http/1.1' or leave ALPN empty.")
  else:
    TlsError(kind: defaultKind, code: baseCode, alertCode: alertCode,
      message: "Fatal TLS alert " & $alertCode & " (" & name & ") " & dir,
      likelyCause: "Peer killed the session with alert '" & name & "'.",
      suggestion: "Try `nimtls probe --insecure <host>` to inspect the handshake.")

proc diagnoseTlsAlert*(alertCode: int, received: bool, serverName = ""): TlsError {.inline.} =
  explainAlert(alertCode, received, serverName)

proc decodeBearErr*(brErr: int, serverName = ""): TlsError =
  if brErr == 0:
    return TlsError(kind: teNone, code: 0, alertCode: -1, message: "No error")

  # BearSSL encodes fatal alerts as 256+alert (recv) and 512+alert (sent)
  if brErr >= 256 and brErr < 512:
    return explainAlert(brErr - 256, received = true, serverName = serverName)
  if brErr >= 512 and brErr < 768:
    return explainAlert(brErr - 512, received = false, serverName = serverName)

  case brErr
  of 1:
    TlsError(kind: teInvalidConfig, code: brErr, alertCode: -1,
      message: "Invalid TLS engine parameter (BR_ERR_BAD_PARAM)",
      likelyCause: "Bad config value or null buffer passed into BearSSL.",
      suggestion: "Check TlsConfig fields (versions, SNI, ALPN, certs).")
  of 2:
    TlsError(kind: teInternalError, code: brErr, alertCode: -1,
      message: "Invalid TLS engine state (BR_ERR_BAD_STATE)",
      likelyCause: "Engine read/write called out of turn.",
      suggestion: "Follow `nextAction()` strictly.")
  of 3, 4:
    TlsError(kind: teProtocolVersionUnsupported, code: brErr, alertCode: -1,
      message: "Unsupported or mismatched TLS version (BR_ERR_" &
               (if brErr == 3: "UNSUPPORTED_VERSION" else: "BAD_VERSION") & ")",
      likelyCause: "Peer speaks an unsupported TLS version or plain HTTP on this port.",
      suggestion: "Make sure the port actually speaks TLS (usually 443) and allows TLS 1.2.")
  of 5, 6:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "Invalid or oversized TLS record (code " & $brErr & ")",
      likelyCause: "Port is probably speaking plaintext HTTP instead of TLS, or record exceeded 16 KB.",
      suggestion: "Verify target host and port speak TLS.")
  of 7:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "Record decryption/MAC failed (BR_ERR_BAD_MAC)",
      likelyCause: "Corrupted stream, broken middlebox, or key state desync.",
      suggestion: "Check for intercepting proxies or packet corruption.")
  of 8:
    TlsError(kind: teInternalError, code: brErr, alertCode: -1,
      message: "No OS entropy available (BR_ERR_NO_RANDOM)",
      likelyCause: "System CSPRNG seeding failed.",
      suggestion: "Make sure /dev/urandom or Windows CryptoAPI is reachable.")
  of 9, 10, 12, 13, 14:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "Malformed or unexpected TLS handshake message (code " & $brErr & ")",
      likelyCause: "Target isn't a TLS server (e.g. plain HTTP on port 80) or middlebox mangled it.",
      suggestion: "Double-check port and proxy/firewall rules.")
  of 16:
    TlsError(kind: teCipherSuiteMismatch, code: brErr, alertCode: -1,
      message: "Incompatible cipher suite (BR_ERR_BAD_CIPHER_SUITE)",
      likelyCause: "Server picked a cipher suite we didn't offer.",
      suggestion: "Check server cipher suite config.")
  of 21:
    TlsError(kind: teHostnameMismatch, code: brErr, alertCode: -1,
      message: "Invalid SNI extension (BR_ERR_BAD_SNI)",
      likelyCause: "Malformed hostname in SNI.",
      suggestion: "Pass a bare hostname with no scheme or port.")
  of 23:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "Cryptographic limit exceeded (BR_ERR_LIMIT_EXCEEDED)",
      likelyCause: "Server cert key (e.g. >4096-bit RSA) blew past BearSSL's static buffers.",
      suggestion: "Inspect the server's key size.")
  of 26, 27:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "Unsupported algorithm or bad handshake signature (code " & $brErr & ")",
      likelyCause: "Peer used an unsupported curve/sig algo (e.g. Ed25519-only) or signature didn't verify.",
      suggestion: "BearSSL supports RSA (PKCS#1 v1.5) and ECDSA (P-256/P-384/P-521) with ECDHE/X25519.")
  of 31:
    TlsError(kind: teIoError, code: brErr, alertCode: -1,
      message: "Transport I/O error or early EOF (BR_ERR_IO)",
      likelyCause: "TCP reset or drop mid-handshake.",
      suggestion: "Check network reachability and firewall.")
  of 33..51:
    TlsError(kind: teCertificateInvalid, code: brErr, alertCode: -1,
      message: "X.509 certificate decode error (BR_ERR_X509 code " & $brErr & ")",
      likelyCause: "Empty/truncated chain, malformed ASN.1, or unsupported extension.",
      suggestion: "Inspect with `nimtls probe --insecure`.")
  of 52:
    TlsError(kind: teCertificateInvalid, code: brErr, alertCode: -1,
      message: "Invalid certificate signature (BR_ERR_X509_BAD_SIGNATURE)",
      likelyCause: "A cert in the chain failed signature verification.",
      suggestion: "Check the server's fullchain ordering and integrity.")
  of 53:
    TlsError(kind: teCertificateExpired, code: brErr, alertCode: -1,
      message: "Validation clock unavailable (BR_ERR_X509_TIME_UNKNOWN)",
      likelyCause: "System clock wasn't available when checking cert dates.",
      suggestion: "Check OS time.")
  of 54:
    TlsError(kind: teCertificateExpired, code: brErr, alertCode: -1,
      message: "Certificate expired or not yet valid (BR_ERR_X509_EXPIRED)",
      likelyCause: "Current UTC time is outside NotBefore..NotAfter.",
      suggestion: "Check system clock or renew the cert.")
  of 55:
    TlsError(kind: teCertificateUntrusted, code: brErr, alertCode: -1,
      message: "Chain Issuer/Subject DN mismatch (BR_ERR_X509_DN_MISMATCH)",
      likelyCause: "Server sent certs out of order or forgot an intermediate CA.",
      suggestion: "Serve the fullchain bundle (leaf + intermediates).")
  of 56:
    let target = if serverName.len > 0: " for '" & serverName & "'" else: ""
    let targetParen = if serverName.len > 0: " ('" & serverName & "')" else: ""
    TlsError(kind: teHostnameMismatch, code: brErr, alertCode: -1,
      message: "Certificate hostname mismatch" & target & " (BR_ERR_X509_BAD_SERVER_NAME)",
      likelyCause: "Cert SANs and CN don't match the requested hostname" & targetParen & ".",
      suggestion: "Use a hostname listed in the cert SANs or override `--sni`.")
  of 57, 58, 59, 60:
    TlsError(kind: teCertificateInvalid, code: brErr, alertCode: -1,
      message: "Cert constraint or key usage violation (BR_ERR_X509 code " & $brErr & ")",
      likelyCause: "Failed BasicConstraints, KeyUsage, unknown critical ext, or tiny RSA key (<1024-bit).",
      suggestion: "Inspect extensions with `nimtls probe --insecure`.")
  of 62:
    TlsError(kind: teCertificateUntrusted, code: brErr, alertCode: -1,
      message: "Certificate chain not trusted (BR_ERR_X509_NOT_TRUSTED)",
      likelyCause: "Self-signed cert, private/corp CA, or missing intermediate.",
      suggestion: "Pass the CA via `SSL_CERT_FILE` / `--ca-file`, or compile with `-d:nimtlsEmbedRoots`.")
  else:
    TlsError(kind: teHandshakeFailed, code: brErr, alertCode: -1,
      message: "TLS engine error (BearSSL code " & $brErr & ")",
      likelyCause: "Unhandled BearSSL error.",
      suggestion: "Run `nimtls probe --insecure` to inspect what happened.")

proc diagnoseBearSslError*(brErr: int, serverName = ""): TlsError {.inline.} =
  decodeBearErr(brErr, serverName)
