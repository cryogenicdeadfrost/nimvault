# Minimal local HTTPS server using mintSelfSigned + wrapServerAsync.
# Build & run: nim c -r examples/local_https_server.nim
# Then test in another terminal: nimvault fetch --insecure https://127.0.0.1:8443/

import std/[asyncdispatch, asyncnet]
import ../src/nimvault

proc handlePeer(raw: AsyncSocket, certPem, keyPem: string) {.async.} =
  let wrapped = await wrapServerAsync(raw, certPem, keyPem)
  if wrapped.isErr:
    raw.close()
    return
  let s = wrapped.val
  let req = await s.recvAsync(4096)
  if req.isOk and req.val.len > 0:
    let body = "hello from nimvault (zero OpenSSL)\n"
    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " &
               $body.len & "\r\nConnection: close\r\n\r\n" & body
    discard await s.sendAsync(resp)
  await s.closeAsync()

proc main() {.async.} =
  let cert = mintSelfSigned(defaultKeygenOptions("localhost")).get()
  let listener = newAsyncSocket(buffered = false)
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(8443), "127.0.0.1")
  listener.listen()
  echo "listening on https://127.0.0.1:8443 (self-signed ", cert.certInfo.sha256Fingerprint[0..22], "...)"

  while true:
    let peer = await listener.accept()
    asyncCheck handlePeer(peer, cert.certificatePem, cert.privateKeyPem)

waitFor main()
