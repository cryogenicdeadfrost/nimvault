# Standalone HTTPS GET with zero -d:ssl and zero OpenSSL.
# Build & run: nim c -r -d:nimvaultEmbedRoots examples/fetch_https.nim

import std/os
import ../src/nimvault

let url = if paramCount() >= 1: paramStr(1) else: "https://example.com/"
let res = fetch(url)
if res.isErr:
  stderr.writeLine(prettyErr(res.err))
  quit(1)

let r = res.val
echo r.statusLine, " (", r.peerInfo.protocolVersion, " / ", r.peerInfo.cipherSuite, ")"
echo "trust: ", r.peerInfo.trustSource, " (", r.peerInfo.trustAnchorCount, " roots)"
echo "body:  ", r.body.len, " bytes"
