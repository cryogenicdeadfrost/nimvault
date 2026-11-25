## End-to-end localhost TCP tests for BOTH sync (`client.nim`) and
## async (`async_client.nim`) adapters using real sockets + BearSSL server.

import std/[unittest, asyncdispatch, asyncnet, net, strutils]
import ../src/nimvault/[errors, engine, keygen, client, async_client]

proc serveOneTlsClient(sock: AsyncSocket, certPem, keyPem: string): Future[void] {.async.} =
  defer: sock.close()
  var srvRes = newServerEngine(defaultServerConfig(certPem, keyPem))
  if not srvRes.isOk:
    return
  let srv = srvRes.val
  var wireBuf: array[4096, byte]
  var appBuf: array[4096, byte]
  var reqAccum = ""

  proc flushOut(): Future[void] {.async.} =
    while srv.needsWrite():
      let n = srv.drainEncrypted(wireBuf)
      if n <= 0: break
      var chunk = newString(n)
      copyMem(addr chunk[0], addr wireBuf[0], n)
      await sock.send(chunk)

  while true:
    case srv.nextAction()
    of taNeedWrite:
      await flushOut()
    of taNeedRead, taReady:
      let data = await sock.recv(4096)
      if data.len == 0:
        break
      var fed = 0
      while fed < data.len:
        let c = srv.feedEncrypted(data.toOpenArrayByte(fed, data.high))
        if c <= 0: break
        fed += c
    of taAppDataReady:
      while srv.hasAppData():
        let n = srv.readPlaintext(appBuf)
        if n <= 0: break
        var s = newString(n)
        copyMem(addr s[0], addr appBuf[0], n)
        reqAccum.add(s)
      if "\r\n\r\n" in reqAccum or reqAccum == "PING":
        let resp = if reqAccum == "PING":
          "PONG"
        else:
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello-from-nimvault-tls"
        var sent = 0
        while sent < resp.len:
          let w = srv.writePlaintext(resp.toOpenArrayByte(sent, resp.high))
          if w > 0:
            sent += w
            srv.flush()
          await flushOut()
        srv.closeNotify()
        await flushOut()
        break
    of taClosed, taError:
      await flushOut()
      break

suite "Sync & Async TCP TLS Adapters (Localhost Server)":
  var opts = defaultKeygenOptions("localhost")
  opts.sanDnsNames = @["localhost"]
  let bundle = generateSelfSignedEcP256(opts).get

  test "Async client connects, exchanges encrypted data, and closes cleanly":
    proc runTest() {.async.} =
      let listener = newAsyncSocket(buffered = false)
      listener.setSockOpt(OptReuseAddr, true)
      listener.bindAddr(Port(0), "127.0.0.1")
      listener.listen()
      let port = int(listener.getLocalAddr()[1])
      defer: listener.close()

      let serverFut = proc() {.async.} =
        let peer = await listener.accept()
        await serveOneTlsClient(peer, bundle.certificatePem, bundle.privateKeyPem)
      let srvTask = serverFut()

      var cfg = defaultTlsConfig("localhost")
      cfg.caPemOverride = bundle.certificatePem

      let connRes = await connectAsync("127.0.0.1", port, cfg)
      check connRes.isOk
      let vs = connRes.val
      check vs.peerInfo().verified
      check vs.peerInfo().protocolVersion == "TLS 1.2"
      check vs.peerInfo().peerCert.subjectCN == "localhost"

      let sRes = await vs.sendAsync("PING")
      check sRes.isOk
      check sRes.val == 4

      let rRes = await vs.recvAsync(1024)
      check rRes.isOk
      check rRes.val == "PONG"

      await vs.closeAsync()
      await srvTask

    waitFor runTest()

  test "Sync client (connect, probe, httpGet) over localhost TCP with threaded server":
    var portChan: Channel[int]
    portChan.open()

    proc serveSyncPeer(peer: Socket, certPem, keyPem: string) =
      defer: peer.close()
      let srvRes = newServerEngine(defaultServerConfig(certPem, keyPem))
      if not srvRes.isOk: return
      let srv = srvRes.val
      var wireBuf: array[4096, byte]
      var appBuf: array[4096, byte]
      var reqAccum = ""

      proc flushOut() =
        while srv.needsWrite():
          let n = srv.drainEncrypted(wireBuf)
          if n <= 0: break
          discard peer.send(addr wireBuf[0], n)

      while true:
        case srv.nextAction()
        of taNeedWrite:
          flushOut()
        of taNeedRead, taReady:
          let n = peer.recv(addr wireBuf[0], wireBuf.len)
          if n <= 0: break
          var fed = 0
          while fed < n:
            let c = srv.feedEncrypted(wireBuf.toOpenArray(fed, n - 1))
            if c <= 0: break
            fed += c
        of taAppDataReady:
          while srv.hasAppData():
            let n = srv.readPlaintext(appBuf)
            if n <= 0: break
            var s = newString(n)
            copyMem(addr s[0], addr appBuf[0], n)
            reqAccum.add(s)
          if "\r\n\r\n" in reqAccum:
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello-from-nimvault-tls"
            var sent = 0
            while sent < resp.len:
              let w = srv.writePlaintext(resp.toOpenArrayByte(sent, resp.high))
              if w > 0:
                sent += w
                srv.flush()
              flushOut()
            srv.closeNotify()
            flushOut()
            break
        of taClosed, taError:
          flushOut()
          break

    proc syncServerThread(args: tuple[chan: ptr Channel[int], certPem: string, keyPem: string]) {.thread.} =
      let listener = newSocket(buffered = false)
      listener.setSockOpt(OptReuseAddr, true)
      listener.bindAddr(Port(0), "127.0.0.1")
      listener.listen()
      let port = int(listener.getLocalAddr()[1])
      args.chan[].send(port)
      defer: listener.close()
      for _ in 0 ..< 2: # handle probe + httpGet
        var peer: Socket
        listener.accept(peer)
        serveSyncPeer(peer, args.certPem, args.keyPem)

    var thr: Thread[tuple[chan: ptr Channel[int], certPem: string, keyPem: string]]
    createThread(thr, syncServerThread, (addr portChan, bundle.certificatePem, bundle.privateKeyPem))
    let port = portChan.recv()
    portChan.close()

    var cfg = defaultTlsConfig("localhost")
    cfg.caPemOverride = bundle.certificatePem

    # 1. Test probe()
    let rep = probe("127.0.0.1", port, cfg, timeoutMs = 5000)
    doAssert rep.success, "probe failed: " & formatDiagnostic(rep.error)
    check rep.peerInfo.verified
    check rep.peerInfo.protocolVersion == "TLS 1.2"
    check rep.peerInfo.peerCert.subjectCN == "localhost"

    # 2. Test httpGet()
    let httpRes = httpGet("127.0.0.1", "/status", port, cfg, timeoutMs = 5000)
    doAssert httpRes.isOk, "httpGet failed: " & formatDiagnostic(httpRes.err)
    check httpRes.val.statusCode == 200
    check httpRes.val.body == "hello-from-nimvault-tls"
    check httpRes.val.peerInfo.verified

    joinThread(thr)
