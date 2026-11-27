# Pure Sans-I/O in-memory TLS 1.2 loopback (zero sockets, zero OS network calls).
# Build & run: nim c -r examples/sans_io_mem.nim

import ../src/nimtls

proc pipeOnce(src, dst: TlsEngine): bool =
  let wire = src.drainEncryptedAll()
  if wire.len == 0: return false
  discard dst.feedEncrypted(wire)
  true

let bundle = mintSelfSigned(defaultKeygenOptions("mem.local")).get()
var cCfg = defaultTlsConfig("mem.local")
cCfg.caPemOverride = bundle.certificatePem

let client = newClientEngine(cCfg).get()
let server = newServerEngine(defaultServerConfig(bundle.certificatePem, bundle.privateKeyPem)).get()

while not (client.isHandshakeDone() and server.isHandshakeDone()):
  discard pipeOnce(client, server)
  discard pipeOnce(server, client)

echo "handshake done: ", client.peerInfo().protocolVersion, " / ", client.peerInfo().cipherSuite

discard client.writePlaintext("ping over raw byte slices")
client.flush()
discard pipeOnce(client, server)

var plain: array[256, byte]
let n = server.readPlaintext(plain)
var msg = newString(n)
copyMem(addr msg[0], addr plain[0], n)
echo "server got: ", msg
