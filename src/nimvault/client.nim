# Sync std/net TLS client/server wrapper + zero-OpenSSL HTTP/1.1 fetch.

import std/[net, nativesockets, strutils, monotimes, times, tables]
import ./errors
import ./engine

const ClientUserAgent* = "nimvault/0.2.0"

type
  VaultSocket* = ref object
    sock*: Socket
    engine*: TlsEngine
    timeoutMs*: int
    closed*: bool

  ProbeReport* = object
    host*: string
    port*: int
    success*: bool
    handshakeMs*: float
    peerInfo*: PeerInfo
    error*: VaultError

  ParsedUrl* = object
    scheme*: string
    host*: string
    port*: int
    path*: string

  HttpResponse* = object
    statusCode*: int
    statusLine*: string
    headers*: Table[string, string]
    body*: string
    finalUrl*: string
    peerInfo*: PeerInfo

proc shoveRaw(sock: Socket, data: openArray[byte]): VaultResult[bool] =
  var sent = 0
  while sent < data.len:
    try:
      let n = sock.send(unsafeAddr data[sent], data.len - sent)
      if n <= 0:
        return err[bool](veIoError, "Socket closed while writing TLS records")
      sent += n
    except CatchableError as e:
      return err[bool](veIoError, "Socket write failed: " & e.msg,
                       likelyCause = "Peer reset connection or network drop.")
  ok(true)

proc flushWire(vs: VaultSocket): VaultResult[bool] =
  var buf: array[4096, byte]
  while vs.engine.needsWrite():
    let n = vs.engine.drainEncrypted(buf)
    if n <= 0: break
    let w = shoveRaw(vs.sock, buf.toOpenArray(0, n - 1))
    if not w.isOk: return w
  ok(true)

proc slurpWire(vs: VaultSocket): VaultResult[int] =
  # std/net's 4-arg recv(buf, size, timeout) loops until the entire 4KB fills, which stalls TLS handshakes.
  # selectRead + 3-arg unbuffered recv returns immediately with whatever bytes hit the kernel buffer.
  var buf: array[4096, byte]
  try:
    if vs.timeoutMs > 0:
      var fds = @[vs.sock.getFd()]
      if selectRead(fds, vs.timeoutMs) == 0:
        return err[int](veIoError, "Socket read timed out after " & $vs.timeoutMs & "ms",
                        likelyCause = "Peer went quiet or firewall ate the packets.",
                        suggestion = "Bump timeout or check host/port reachability.")
    let n = vs.sock.recv(addr buf[0], buf.len)
    if n <= 0: return ok(0)
    var fed = 0
    while fed < n:
      let c = vs.engine.feedEncrypted(buf.toOpenArray(fed, n - 1))
      if c <= 0: break
      fed += c
    return ok(n)
  except CatchableError as e:
    return err[int](veIoError, "Socket read failed: " & e.msg,
                    likelyCause = "Connection reset by peer or network blip.")

proc close*(vs: VaultSocket) =
  if vs == nil or vs.closed: return
  vs.closed = true
  try:
    vs.engine.closeNotify()
    discard flushWire(vs)
  except CatchableError:
    discard
  vs.engine.close()
  if vs.sock != nil:
    try: vs.sock.close()
    except CatchableError: discard

proc peerInfo*(vs: VaultSocket): PeerInfo =
  if vs == nil: return PeerInfo()
  vs.engine.peerInfo()

proc crankHandshake(vs: VaultSocket): VaultResult[bool] =
  while true:
    case vs.engine.nextAction()
    of taNeedWrite:
      let w = flushWire(vs)
      if not w.isOk: return w
    of taNeedRead:
      let r = slurpWire(vs)
      if not r.isOk: return err[bool](r.err)
      if r.val == 0:
        if vs.engine.rawErrorCode() != 0:
          return err[bool](vs.engine.lastError())
        return err[bool](
          veIoError,
          "Peer closed TCP socket mid-handshake",
          likelyCause = "Server rejected the ClientHello, requires TLS 1.3 only, or isn't speaking TLS on this port.",
          suggestion = "Check port, SNI, and TLS 1.2 support."
        )
    of taReady, taAppDataReady:
      return ok(true)
    of taError:
      discard flushWire(vs)
      return err[bool](vs.engine.lastError())
    of taClosed:
      return err[bool](veConnectionClosed, "TLS engine closed during handshake")

proc connect*(host: string, port = 443, config = defaultTlsConfig(),
              timeoutMs = 10_000): VaultResult[VaultSocket] =
  var cfg = config
  if cfg.serverName.len == 0: cfg.serverName = host

  let engRes = newClientEngine(cfg)
  if not engRes.isOk: return err[VaultSocket](engRes.err)

  let sock = newSocket(buffered = false)
  try:
    sock.connect(host, Port(port), timeout = timeoutMs)
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    return err[VaultSocket](
      veIoError,
      "TCP connect to " & host & ":" & $port & " failed: " & e.msg,
      likelyCause = "DNS failed, host unreachable, or port refused.",
      suggestion = "Check hostname, port, and network connectivity."
    )

  let vs = VaultSocket(sock: sock, engine: engRes.val, timeoutMs: timeoutMs, closed: false)
  let hs = crankHandshake(vs)
  if not hs.isOk:
    vs.close()
    return err[VaultSocket](hs.err)
  ok(vs)

proc dial*(host: string, port = 443, config = defaultTlsConfig(),
           timeoutMs = 10_000): VaultResult[VaultSocket] {.inline.} =
  connect(host, port, config, timeoutMs)

proc wrapServer*(sock: Socket, certPem, keyPem: string,
                 alpnProtocols: seq[string] = @[],
                 timeoutMs = 10_000): VaultResult[VaultSocket] =
  # Wraps an already-accepted unbuffered std/net Socket and completes the server TLS handshake.
  var cfg = defaultServerConfig(certPem, keyPem)
  cfg.alpnProtocols = alpnProtocols
  let engRes = newServerEngine(cfg)
  if not engRes.isOk: return err[VaultSocket](engRes.err)

  let vs = VaultSocket(sock: sock, engine: engRes.val, timeoutMs: timeoutMs, closed: false)
  let hs = crankHandshake(vs)
  if not hs.isOk:
    vs.engine.close()
    return err[VaultSocket](hs.err)
  ok(vs)

proc probe*(host: string, port = 443, config = defaultTlsConfig(),
            timeoutMs = 10_000): ProbeReport =
  var cfg = config
  if cfg.serverName.len == 0: cfg.serverName = host

  result = ProbeReport(host: host, port: port, success: false)

  let engRes = newClientEngine(cfg)
  if not engRes.isOk:
    result.error = engRes.err
    return result

  let t0 = getMonoTime()
  let sock = newSocket(buffered = false)
  try:
    sock.connect(host, Port(port), timeout = timeoutMs)
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    result.error = VaultError(
      kind: veIoError,
      alertCode: -1,
      message: "TCP connect to " & host & ":" & $port & " failed: " & e.msg,
      likelyCause: "DNS failed, host unreachable, or port refused.",
      suggestion: "Check hostname, port, and network connectivity."
    )
    return result

  let vs = VaultSocket(sock: sock, engine: engRes.val, timeoutMs: timeoutMs, closed: false)
  let hs = crankHandshake(vs)
  result.handshakeMs = inMicroseconds(getMonoTime() - t0).float / 1000.0
  result.peerInfo = vs.engine.peerInfo()
  if hs.isOk:
    result.success = true
  else:
    result.error = hs.err
  vs.close()

proc poke*(host: string, port = 443, config = defaultTlsConfig(),
           timeoutMs = 10_000): ProbeReport {.inline.} =
  probe(host, port, config, timeoutMs)

proc send*(vs: VaultSocket, data: openArray[byte]): VaultResult[int] =
  if vs == nil or vs.closed:
    return err[int](veConnectionClosed, "Cannot send on closed VaultSocket")
  var offset = 0
  while offset < data.len:
    if vs.engine.canWriteAppData():
      let n = vs.engine.writePlaintext(data.toOpenArray(offset, data.high))
      if n > 0:
        offset += n
        vs.engine.flush()
    let w = flushWire(vs)
    if not w.isOk: return err[int](w.err)
    let act = vs.engine.nextAction()
    if act == taError: return err[int](vs.engine.lastError())
    elif act == taClosed: return err[int](veConnectionClosed, "TLS connection closed during send")
  ok(offset)

proc send*(vs: VaultSocket, text: string): VaultResult[int] =
  if text.len == 0: return ok(0)
  vs.send(text.toOpenArrayByte(0, text.high))

proc recv*(vs: VaultSocket, maxBytes = 4096): VaultResult[string] =
  if vs == nil or vs.closed: return ok("")
  var outBuf = newSeq[byte](max(1, maxBytes))
  while true:
    if vs.engine.hasAppData():
      let n = vs.engine.readPlaintext(outBuf)
      if n > 0:
        var s = newString(n)
        copyMem(addr s[0], addr outBuf[0], n)
        return ok(s)

    case vs.engine.nextAction()
    of taAppDataReady: continue
    of taNeedWrite:
      let w = flushWire(vs)
      if not w.isOk: return err[string](w.err)
    of taNeedRead, taReady:
      let r = slurpWire(vs)
      if not r.isOk: return err[string](r.err)
      if r.val == 0:
        if vs.engine.rawErrorCode() != 0:
          return err[string](vs.engine.lastError())
        return ok("")
    of taClosed: return ok("")
    of taError: return err[string](vs.engine.lastError())

proc crackUrl*(rawUrl: string): VaultResult[ParsedUrl] =
  var s = rawUrl.strip()
  if s.len == 0:
    return err[ParsedUrl](veInvalidConfig, "URL cannot be empty")
  var scheme = "https"
  let schemeIdx = s.find("://")
  if schemeIdx >= 0:
    scheme = s[0 ..< schemeIdx].toLowerAscii()
    s = s[schemeIdx + 3 .. ^1]
  if scheme != "https":
    return err[ParsedUrl](
      veInvalidConfig,
      "Unsupported URL scheme '" & scheme & "' (nimvault fetch speaks https://)",
      suggestion = "Use an https:// URL."
    )

  var hostPort = s
  var path = "/"
  let slashIdx = s.find('/')
  if slashIdx >= 0:
    hostPort = s[0 ..< slashIdx]
    path = s[slashIdx .. ^1]

  var host = hostPort
  var port = 443
  let colonIdx = hostPort.rfind(':')
  if colonIdx > 0 and not hostPort.endsWith("]"):
    try:
      port = parseInt(hostPort[colonIdx + 1 .. ^1])
      host = hostPort[0 ..< colonIdx]
    except ValueError:
      return err[ParsedUrl](veInvalidConfig, "Invalid port in URL: " & rawUrl)

  if host.len == 0 or port <= 0 or port > 65535:
    return err[ParsedUrl](veInvalidConfig, "Invalid host or port in URL: " & rawUrl)

  ok(ParsedUrl(scheme: scheme, host: host, port: port, path: path))

proc parseHttpsUrl*(rawUrl: string): VaultResult[ParsedUrl] {.inline.} = crackUrl(rawUrl)

proc dechunkBody(raw: string): string =
  # RFC 9112 chunked transfer decoding: <hex-len>\r\n<bytes>\r\n ... 0\r\n\r\n
  var pos = 0
  result = newStringOfCap(raw.len)
  while pos < raw.len:
    let crlf = raw.find("\r\n", pos)
    if crlf < 0: break
    var sizeLine = raw[pos ..< crlf].strip()
    let semi = sizeLine.find(';') # ignore optional chunk extensions
    if semi >= 0: sizeLine = sizeLine[0 ..< semi].strip()
    if sizeLine.len == 0: break
    var chunkLen = 0
    try:
      chunkLen = fromHex[int](sizeLine)
    except ValueError:
      return raw # malformed chunk header, fall back to raw bytes
    pos = crlf + 2
    if chunkLen == 0: break
    let stop = min(pos + chunkLen, raw.len)
    result.add(raw[pos ..< stop])
    pos = stop
    if pos + 1 < raw.len and raw[pos] == '\r' and raw[pos + 1] == '\n':
      pos += 2

proc httpRequest*(meth: string, host: string, path = "/", port = 443,
                  headers: openArray[(string, string)] = @[],
                  body = "", config = defaultTlsConfig(),
                  timeoutMs = 10_000): VaultResult[HttpResponse] =
  var cfg = config
  if cfg.serverName.len == 0: cfg.serverName = host
  if cfg.alpnProtocols.len == 0: cfg.alpnProtocols = @["http/1.1"]

  let connRes = connect(host, port, cfg, timeoutMs)
  if not connRes.isOk: return err[HttpResponse](connRes.err)
  let vs = connRes.val
  defer: vs.close()

  let reqPath = if path.len == 0: "/" else: path
  let hostHeader = if port == 443: host else: host & ":" & $port
  var req = meth.toUpperAscii() & " " & reqPath & " HTTP/1.1\r\n" &
            "Host: " & hostHeader & "\r\n" &
            "User-Agent: " & ClientUserAgent & "\r\n" &
            "Accept: */*\r\n" &
            "Connection: close\r\n"

  var hasContentLen = false
  for (k, v) in headers:
    if k.toLowerAscii() == "content-length": hasContentLen = true
    req.add(k & ": " & v & "\r\n")
  if body.len > 0 and not hasContentLen:
    req.add("Content-Length: " & $body.len & "\r\n")
  req.add("\r\n")
  if body.len > 0: req.add(body)

  let sendRes = vs.send(req)
  if not sendRes.isOk: return err[HttpResponse](sendRes.err)

  var raw = ""
  while true:
    let chunkRes = vs.recv(8192)
    if not chunkRes.isOk:
      if raw.len > 0: break
      return err[HttpResponse](chunkRes.err)
    if chunkRes.val.len == 0: break
    raw.add(chunkRes.val)

  var resp = HttpResponse(
    headers: initTable[string, string](),
    finalUrl: "https://" & hostHeader & reqPath,
    peerInfo: vs.peerInfo()
  )
  let sep = raw.find("\r\n\r\n")
  let headerPart = if sep >= 0: raw[0 ..< sep] else: raw
  var respBody = if sep >= 0: raw[sep + 4 .. ^1] else: ""

  let headerLines = headerPart.split("\r\n")
  if headerLines.len > 0:
    resp.statusLine = headerLines[0]
    let parts = headerLines[0].split(' ')
    if parts.len >= 2:
      try: resp.statusCode = parseInt(parts[1])
      except ValueError: resp.statusCode = 0
    for i in 1 ..< headerLines.len:
      let colon = headerLines[i].find(':')
      if colon > 0:
        resp.headers[headerLines[i][0 ..< colon].strip().toLowerAscii()] =
          headerLines[i][colon + 1 .. ^1].strip()

  if resp.headers.getOrDefault("transfer-encoding").toLowerAscii().contains("chunked"):
    respBody = dechunkBody(respBody)
  resp.body = respBody
  ok(resp)

proc httpGet*(host: string, path = "/", port = 443,
              config = defaultTlsConfig(), timeoutMs = 10_000): VaultResult[HttpResponse] =
  httpRequest("GET", host, path, port, @[], "", config, timeoutMs)

proc fetch*(url: string, meth = "GET",
            headers: openArray[(string, string)] = @[],
            body = "", config = defaultTlsConfig(),
            timeoutMs = 10_000, maxRedirects = 5): VaultResult[HttpResponse] =
  # Standalone HTTPS URL fetch with chunked decoding and redirect following.
  var curUrl = url
  var curMeth = meth.toUpperAscii()
  var curBody = body

  for _ in 0 .. maxRedirects:
    let uRes = crackUrl(curUrl)
    if not uRes.isOk: return err[HttpResponse](uRes.err)
    let u = uRes.val

    var reqCfg = config
    if config.serverName.len == 0:
      reqCfg.serverName = u.host

    let res = httpRequest(curMeth, u.host, u.path, u.port, headers, curBody, reqCfg, timeoutMs)
    if not res.isOk: return res
    let resp = res.val

    if resp.statusCode in [301, 302, 303, 307, 308] and resp.headers.hasKey("location"):
      let loc = resp.headers["location"]
      if loc.startsWith("https://"):
        curUrl = loc
      elif loc.startsWith("/"):
        let hostPort = if u.port == 443: u.host else: u.host & ":" & $u.port
        curUrl = "https://" & hostPort & loc
      else:
        return ok(resp)
      if resp.statusCode == 303:
        curMeth = "GET"
        curBody = ""
      continue
    return ok(resp)

  err[HttpResponse](veIoError, "Exceeded maximum redirect limit (" & $maxRedirects & ")")

proc httpPost*(url: string, body: string, contentType = "application/json",
               headers: openArray[(string, string)] = @[],
               config = defaultTlsConfig(), timeoutMs = 10_000): VaultResult[HttpResponse] =
  var hdrs: seq[(string, string)] = @[("Content-Type", contentType)]
  for h in headers: hdrs.add(h)
  fetch(url, meth = "POST", headers = hdrs, body = body, config = config, timeoutMs = timeoutMs)
