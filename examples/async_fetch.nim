# Async TLS client on std/asyncdispatch.
# Build & run: nim c -r -d:nimtlsEmbedRoots examples/async_fetch.nim

import std/asyncdispatch
import ../src/nimtls

proc main() {.async.} =
  let conn = await dialAsync("example.com", 443)
  if conn.isErr:
    stderr.writeLine(prettyErr(conn.err))
    quit(1)

  let s = conn.val
  echo "connected: ", s.peerInfo().protocolVersion, " / ", s.peerInfo().cipherSuite
  discard await s.sendAsync("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
  let chunk = await s.recvAsync(4096)
  if chunk.isOk: echo chunk.val
  await s.closeAsync()

waitFor main()
