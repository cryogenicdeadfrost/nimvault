import std/[unittest, strutils, times]
import ../src/nimtls/[errors, engine, keygen]

proc pumpPair(client: TlsEngine, server: TlsEngine, maxSteps = 200): tuple[ok: bool, clientErr: TlsError, serverErr: TlsError] =
  ## Pure in-memory Sans-I/O pump connecting a client and server engine with zero sockets.
  var buf: array[4096, byte]
  for _ in 0 ..< maxSteps:
    var progressed = false

    if client.needsWrite():
      let n = client.drainEncrypted(buf)
      if n > 0:
        var fed = 0
        while fed < n:
          let c = server.feedEncrypted(buf.toOpenArray(fed, n - 1))
          if c <= 0: break
          fed += c
        progressed = true

    if server.needsWrite():
      let n = server.drainEncrypted(buf)
      if n > 0:
        var fed = 0
        while fed < n:
          let c = client.feedEncrypted(buf.toOpenArray(fed, n - 1))
          if c <= 0: break
          fed += c
        progressed = true

    let ca = client.nextAction()
    let sa = server.nextAction()

    if ca == taError or sa == taError:
      return (false, client.lastError(), server.lastError())

    if client.isHandshakeDone() and server.isHandshakeDone() and not client.needsWrite() and not server.needsWrite():
      return (true, TlsError(), TlsError())

    if not progressed:
      break

  (false, client.lastError(), server.lastError())

proc transferApp(sender: TlsEngine, receiver: TlsEngine, payload: string): string =
  var sent = 0
  var wireBuf: array[4096, byte]
  var readBuf: array[4096, byte]
  while sent < payload.len or sender.needsWrite() or result.len < payload.len:
    if sent < payload.len and sender.canWriteAppData():
      let n = sender.writePlaintext(payload.toOpenArrayByte(sent, payload.high))
      if n > 0:
        sent += n
        sender.flush()
    while sender.needsWrite():
      let wn = sender.drainEncrypted(wireBuf)
      if wn <= 0: break
      var fed = 0
      while fed < wn:
        let fc = receiver.feedEncrypted(wireBuf.toOpenArray(fed, wn - 1))
        if fc <= 0: break
        fed += fc
        while receiver.hasAppData():
          let rn = receiver.readPlaintext(readBuf)
          if rn <= 0: break
          let oldLen = result.len
          result.setLen(oldLen + rn)
          copyMem(addr result[oldLen], addr readBuf[0], rn)
    while receiver.hasAppData():
      let rn = receiver.readPlaintext(readBuf)
      if rn <= 0: break
      let oldLen = result.len
      result.setLen(oldLen + rn)
      copyMem(addr result[oldLen], addr readBuf[0], rn)
    if sender.nextAction() == taError or receiver.nextAction() == taError:
      break

suite "Sans-I/O TlsEngine In-Memory Loopback":
  var opts = defaultKeygenOptions("loopback.nimtls.test")
  opts.sanDnsNames = @["loopback.nimtls.test", "alt.nimtls.test"]
  let certRes = generateSelfSignedEcP256(opts)
  doAssert certRes.isOk, certRes.err.message
  let serverBundle = certRes.val

  test "Verified TLS 1.2 handshake, ALPN, PeerInfo, 32KB bidirectional payload, and close_notify":
    var cCfg = defaultTlsConfig("loopback.nimtls.test")
    cCfg.caPemOverride = serverBundle.certificatePem
    cCfg.alpnProtocols = @["h2", "http/1.1"]

    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)
    sCfg.alpnProtocols = @["http/1.1"]

    var clientRes = newClientEngine(cCfg)
    var serverRes = newServerEngine(sCfg)
    check clientRes.isOk
    check serverRes.isOk

    let client = clientRes.val
    let server = serverRes.val

    let hs = pumpPair(client, server)
    check hs.ok

    let pInfo = client.peerInfo()
    check pInfo.protocolVersion == "TLS 1.2"
    check "ECDHE_ECDSA" in pInfo.cipherSuite
    check pInfo.selectedAlpn == "http/1.1"
    check pInfo.verified
    check pInfo.hasPeerCert
    check pInfo.peerCert.subjectCN == "loopback.nimtls.test"
    check pInfo.chainLength == 1

    # 32KB multi-record bidirectional encrypted transfer
    let clientMsg = repeat("NimTLS-SansIO-Client->Server!", 1024)
    let gotOnServer = transferApp(client, server, clientMsg)
    check gotOnServer == clientMsg

    let serverMsg = repeat("NimTLS-SansIO-Server->Client!", 1024)
    let gotOnClient = transferApp(server, client, serverMsg)
    check gotOnClient == serverMsg

    # Clean bidirectional close_notify shutdown
    client.closeNotify()
    let cClose = client.drainEncryptedAll()
    check cClose.len > 0
    discard server.feedEncrypted(cClose)
    # BearSSL automatically replies with server close_notify upon receiving client close_notify
    let sClose = server.drainEncryptedAll()
    check sClose.len > 0
    discard client.feedEncrypted(sClose)
    check client.nextAction() == taClosed
    check server.nextAction() == taClosed
    check client.rawErrorCode() == 0
    check server.rawErrorCode() == 0

  test "Hostname mismatch produces actionable teHostnameMismatch and still captures leaf cert":
    var cCfg = defaultTlsConfig("wrong-host.example")
    cCfg.caPemOverride = serverBundle.certificatePem
    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)

    var client = newClientEngine(cCfg).get
    var server = newServerEngine(sCfg).get

    let hs = pumpPair(client, server)
    check not hs.ok
    check hs.clientErr.kind == teHostnameMismatch
    check "wrong-host.example" in hs.clientErr.message

    let pInfo = client.peerInfo()
    check not pInfo.verified
    check pInfo.hasPeerCert
    check pInfo.peerCert.subjectCN == "loopback.nimtls.test"

  test "Untrusted root CA produces actionable teCertificateUntrusted":
    let otherCa = generateSelfSignedEcP256(defaultKeygenOptions("unrelated-ca.test")).get
    var cCfg = defaultTlsConfig("loopback.nimtls.test")
    cCfg.caPemOverride = otherCa.certificatePem
    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)

    var client = newClientEngine(cCfg).get
    var server = newServerEngine(sCfg).get

    let hs = pumpPair(client, server)
    check not hs.ok
    check hs.clientErr.kind == teCertificateUntrusted

  test "Expired certificate produces actionable teCertificateExpired":
    var cCfg = defaultTlsConfig("loopback.nimtls.test")
    cCfg.caPemOverride = serverBundle.certificatePem
    # 10 years in the future
    cCfg.validationTimeUnix = uint64(getTime().toUnix() + 10 * 365 * 86400)
    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)

    var client = newClientEngine(cCfg).get
    var server = newServerEngine(sCfg).get

    let hs = pumpPair(client, server)
    check not hs.ok
    check hs.clientErr.kind == teCertificateExpired

  test "insecureSkipVerify allows inspecting untrusted / mismatched peer certs":
    var cCfg = defaultTlsConfig("wrong-host.example")
    cCfg.insecureSkipVerify = true
    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)

    var client = newClientEngine(cCfg).get
    var server = newServerEngine(sCfg).get

    let hs = pumpPair(client, server)
    check hs.ok
    let pInfo = client.peerInfo()
    check not pInfo.verified
    check pInfo.hasPeerCert
    check pInfo.peerCert.subjectCN == "loopback.nimtls.test"

  test "Strict ALPN mismatch fails with actionable teAlpnMismatch":
    var cCfg = defaultTlsConfig("loopback.nimtls.test")
    cCfg.caPemOverride = serverBundle.certificatePem
    cCfg.alpnProtocols = @["custom-proto/1"]
    cCfg.failOnAlpnMismatch = true

    var sCfg = defaultServerConfig(serverBundle.certificatePem, serverBundle.privateKeyPem)
    sCfg.alpnProtocols = @["http/1.1"]
    sCfg.failOnAlpnMismatch = true

    var client = newClientEngine(cCfg).get
    var server = newServerEngine(sCfg).get

    let hs = pumpPair(client, server)
    check not hs.ok
    check hs.clientErr.kind == teAlpnMismatch
