# CLI frontend: trust, probe, fetch, keygen, version.

import std/[os, strutils, json, tables]
import ./errors
import ./truststore
import ./x509
import ./engine
import ./client
import ./keygen

const NimtlsVersion* = "0.3.1"

proc printUsage() =
  echo """nimtls """ & NimtlsVersion & """ (BearSSL 0.6 static TLS, zero OpenSSL)

Usage:
  nimtls trust   [options]             Show which CA trust store won
  nimtls probe   <host[:port]> [opts]  Run a TLS handshake and inspect cert / errors
  nimtls fetch   <https://url> [opts]  Minimal HTTPS GET/HEAD without curl or OpenSSL
  nimtls keygen  [options]             Mint an ECDSA P-256 key + self-signed X.509 v3 cert
  nimtls version                       Show build info

Trust options:
  --ca-file <path>      Validate a specific PEM CA bundle
  --no-embedded         Don't fall back to compiled-in Mozilla roots
  --json                JSON output

Probe options:
  --port <num>          Target port (default: 443)
  --sni <hostname>      Override SNI / cert hostname check
  --ca-file <path>      Custom PEM CA bundle
  --alpn <proto>        Offer ALPN protocol (repeatable)
  --timeout <ms>        Socket timeout in ms (default: 10000)
  --insecure            Skip cert verification (debugging only)
  --json                JSON output

Fetch options:
  --head                Send HEAD instead of GET
  --headers             Print response status + headers before body
  --ca-file <path>      Custom PEM CA bundle
  --timeout <ms>        Socket timeout in ms (default: 10000)
  --insecure            Skip cert verification

Keygen options:
  --cn <name>           Common Name (default: localhost)
  --org <name>          Organization (default: nimtls-dev)
  --san <dns>           SAN DNS entry (repeatable)
  --days <num>          Validity in days (default: 365)
  --key-out <path>      Write PKCS#8 private key PEM
  --cert-out <path>     Write X.509 cert PEM"""

proc tryFlagInt(flag, raw: string, dest: var int): bool =
  try:
    dest = parseInt(raw)
    if dest <= 0:
      stderr.writeLine("Error: ", flag, " must be > 0 (got '", raw, "')")
      return false
    true
  except ValueError:
    stderr.writeLine("Error: ", flag, " expects an integer (got '", raw, "')")
    false

proc cmdVersion(): int =
  echo "nimtls ", NimtlsVersion
  echo "  TLS Backend:     BearSSL 0.6 (static, zero OpenSSL)"
  echo "  TLS Versions:    TLS 1.0 - TLS 1.2 (AES-GCM, ChaCha20-Poly1305)"
  echo "  Embedded Roots:  ", (if hasEmbeddedRoots(): "enabled (Mozilla bundle baked in)" else: "disabled (pass -d:nimtlsEmbedRoots)")
  0

proc cmdTrust(args: seq[string]): int =
  var caFile = ""
  var allowEmbedded = true
  var jsonOut = false

  var i = 0
  while i < args.len:
    case args[i]
    of "--ca-file":
      if i + 1 >= args.len: stderr.writeLine("Error: --ca-file needs a path"); return 2
      inc i; caFile = args[i]
    of "--no-embedded": allowEmbedded = false
    of "--json": jsonOut = true
    of "-h", "--help": printUsage(); return 0
    else:
      stderr.writeLine("Unknown option for `trust`: ", args[i])
      return 2
    inc i

  let res = resolveTrustStore(explicitPath = caFile, allowEmbeddedFallback = allowEmbedded)
  if not res.isOk:
    if jsonOut:
      echo (%*{
        "ok": false,
        "embeddedRootsAvailable": hasEmbeddedRoots(),
        "error": {
          "kind": $res.err.kind,
          "message": res.err.message,
          "likelyCause": res.err.likelyCause,
          "suggestion": res.err.suggestion
        }
      }).pretty()
    else:
      stderr.writeLine(prettyErr(res.err))
    return 1

  let b = res.val
  if jsonOut:
    echo (%*{
      "ok": true,
      "sourceKind": $b.sourceKind,
      "sourcePath": b.sourcePath,
      "certCount": b.certCount,
      "pemBytes": b.pemData.len,
      "embeddedRootsAvailable": hasEmbeddedRoots()
    }).pretty()
  else:
    echo "Trust Store: OK"
    echo "  Source Kind:     ", b.sourceKind
    echo "  Source Path:     ", b.sourcePath
    echo "  Certificates:    ", b.certCount
    echo "  PEM Size:        ", b.pemData.len, " bytes"
    echo "  Embedded Roots:  ", (if hasEmbeddedRoots(): "compiled in" else: "not compiled in")
  0

proc splitHostPort(target: string, defaultPort: int): tuple[host: string, port: int] =
  var clean = target.strip()
  if clean.startsWith("https://"): clean = clean[8 .. ^1]
  elif clean.startsWith("http://"): clean = clean[7 .. ^1]
  let slash = clean.find('/')
  if slash >= 0: clean = clean[0 ..< slash]
  let colon = clean.rfind(':')
  if colon > 0 and not clean.endsWith("]"):
    try: return (clean[0 ..< colon], parseInt(clean[colon + 1 .. ^1]))
    except ValueError: discard
  (clean, defaultPort)

proc cmdProbe(args: seq[string]): int =
  var target = ""
  var portOverride = -1
  var sni = ""
  var caFile = ""
  var alpn: seq[string] = @[]
  var timeoutMs = 10_000
  var insecure = false
  var jsonOut = false

  var i = 0
  while i < args.len:
    case args[i]
    of "--port":
      if i + 1 >= args.len: stderr.writeLine("Error: --port needs a number"); return 2
      inc i
      if not tryFlagInt("--port", args[i], portOverride): return 2
    of "--sni":
      if i + 1 >= args.len: stderr.writeLine("Error: --sni needs a hostname"); return 2
      inc i; sni = args[i]
    of "--ca-file":
      if i + 1 >= args.len: stderr.writeLine("Error: --ca-file needs a path"); return 2
      inc i; caFile = args[i]
    of "--alpn":
      if i + 1 >= args.len: stderr.writeLine("Error: --alpn needs a protocol"); return 2
      inc i; alpn.add(args[i])
    of "--timeout":
      if i + 1 >= args.len: stderr.writeLine("Error: --timeout needs milliseconds"); return 2
      inc i
      if not tryFlagInt("--timeout", args[i], timeoutMs): return 2
    of "--insecure": insecure = true
    of "--json": jsonOut = true
    of "-h", "--help": printUsage(); return 0
    else:
      if args[i].startsWith("-"):
        stderr.writeLine("Unknown option for `probe`: ", args[i]); return 2
      if target.len == 0: target = args[i]
      else: stderr.writeLine("Unexpected argument: ", args[i]); return 2
    inc i

  if target.len == 0:
    stderr.writeLine("Usage: nimtls probe <host[:port]> [options]")
    return 2

  var (host, port) = splitHostPort(target, 443)
  if portOverride > 0: port = portOverride

  var cfg = defaultTlsConfig(if sni.len > 0: sni else: host)
  cfg.caBundlePath = caFile
  cfg.insecureSkipVerify = insecure
  cfg.alpnProtocols = if alpn.len > 0: alpn else: @["http/1.1"]

  let rep = probe(host, port, cfg, timeoutMs)

  if jsonOut:
    var certObj = newJNull()
    if rep.peerInfo.hasPeerCert:
      let c = rep.peerInfo.peerCert
      certObj = %*{
        "version": c.version, "subject": c.subject, "subjectCN": c.subjectCN,
        "issuer": c.issuer, "issuerCN": c.issuerCN,
        "notBefore": c.notBefore, "notAfter": c.notAfter,
        "sanDnsNames": c.sanDnsNames, "sanIps": c.sanIps,
        "keyAlgorithm": c.keyAlgorithm, "sigAlgorithm": c.sigAlgorithm,
        "sha256Fingerprint": c.sha256Fingerprint
      }
    var errObj = newJNull()
    if not rep.success:
      errObj = %*{
        "kind": $rep.error.kind, "code": rep.error.code, "alertCode": rep.error.alertCode,
        "message": rep.error.message, "likelyCause": rep.error.likelyCause,
        "suggestion": rep.error.suggestion
      }
    echo (%*{
      "host": rep.host, "port": rep.port, "success": rep.success,
      "handshakeMs": rep.handshakeMs,
      "protocolVersion": rep.peerInfo.protocolVersion,
      "cipherSuite": rep.peerInfo.cipherSuite,
      "selectedAlpn": rep.peerInfo.selectedAlpn,
      "verified": rep.peerInfo.verified,
      "chainLength": rep.peerInfo.chainLength,
      "trustSource": rep.peerInfo.trustSource,
      "trustAnchorCount": rep.peerInfo.trustAnchorCount,
      "peerCertificate": certObj,
      "error": errObj
    }).pretty()
    return if rep.success: 0 else: 1

  echo "TLS Probe: ", rep.host, ":", rep.port
  echo "  Status:          ", (if rep.success: "OK" else: "FAILED")
  echo "  Handshake Time:  ", formatFloat(rep.handshakeMs, ffDecimal, 2), " ms"
  echo "  Protocol:        ", rep.peerInfo.protocolVersion
  echo "  Cipher Suite:    ", rep.peerInfo.cipherSuite
  if rep.peerInfo.selectedAlpn.len > 0:
    echo "  ALPN:            ", rep.peerInfo.selectedAlpn
  echo "  Trust Source:    ", rep.peerInfo.trustSource,
       (if rep.peerInfo.trustAnchorCount > 0: " (" & $rep.peerInfo.trustAnchorCount & " anchors)" else: "")
  echo "  Verified:        ", (if rep.peerInfo.verified: "yes" elif insecure: "skipped (--insecure)" else: "no")

  if rep.peerInfo.hasPeerCert:
    let c = rep.peerInfo.peerCert
    echo "  Leaf Certificate (chain length: ", rep.peerInfo.chainLength, "):"
    echo "    Subject:       ", c.subject
    echo "    Issuer:        ", c.issuer
    echo "    Valid From:    ", c.notBefore
    echo "    Valid Until:   ", c.notAfter
    echo "    Key / Sig:     ", c.keyAlgorithm, " / ", c.sigAlgorithm
    if c.sanDnsNames.len > 0: echo "    SAN DNS:       ", c.sanDnsNames.join(", ")
    echo "    SHA-256:       ", c.sha256Fingerprint

  if not rep.success:
    echo ""
    stderr.writeLine(prettyErr(rep.error))
    return 1
  0

proc cmdFetch(args: seq[string]): int =
  var url = ""
  var meth = "GET"
  var showHeaders = false
  var caFile = ""
  var timeoutMs = 10_000
  var insecure = false

  var i = 0
  while i < args.len:
    case args[i]
    of "--head": meth = "HEAD"; showHeaders = true
    of "--headers": showHeaders = true
    of "--ca-file":
      if i + 1 >= args.len: stderr.writeLine("Error: --ca-file needs a path"); return 2
      inc i; caFile = args[i]
    of "--timeout":
      if i + 1 >= args.len: stderr.writeLine("Error: --timeout needs ms"); return 2
      inc i
      if not tryFlagInt("--timeout", args[i], timeoutMs): return 2
    of "--insecure": insecure = true
    of "-h", "--help": printUsage(); return 0
    else:
      if args[i].startsWith("-"):
        stderr.writeLine("Unknown option for `fetch`: ", args[i]); return 2
      if url.len == 0: url = args[i]
      else: stderr.writeLine("Unexpected argument: ", args[i]); return 2
    inc i

  if url.len == 0:
    stderr.writeLine("Usage: nimtls fetch <https://url> [options]")
    return 2

  var cfg = defaultTlsConfig()
  cfg.caBundlePath = caFile
  cfg.insecureSkipVerify = insecure

  let res = fetch(url, meth = meth, config = cfg, timeoutMs = timeoutMs)
  if not res.isOk:
    stderr.writeLine(prettyErr(res.err))
    return 1

  let resp = res.val
  if showHeaders:
    echo resp.statusLine
    for k, v in resp.headers:
      echo k, ": ", v
    echo ""
  if resp.body.len > 0:
    stdout.write(resp.body)
  0

proc cmdKeygen(args: seq[string]): int =
  var opts = defaultKeygenOptions("localhost")
  opts.sanDnsNames = @[]
  var keyOut = ""
  var certOut = ""

  var i = 0
  while i < args.len:
    case args[i]
    of "--cn":
      if i + 1 >= args.len: stderr.writeLine("Error: --cn needs a value"); return 2
      inc i; opts.commonName = args[i]
    of "--org":
      if i + 1 >= args.len: stderr.writeLine("Error: --org needs a value"); return 2
      inc i; opts.organization = args[i]
    of "--san":
      if i + 1 >= args.len: stderr.writeLine("Error: --san needs a DNS name"); return 2
      inc i; opts.sanDnsNames.add(args[i])
    of "--days":
      if i + 1 >= args.len: stderr.writeLine("Error: --days needs a number"); return 2
      inc i
      if not tryFlagInt("--days", args[i], opts.validDays): return 2
    of "--key-out":
      if i + 1 >= args.len: stderr.writeLine("Error: --key-out needs a path"); return 2
      inc i; keyOut = args[i]
    of "--cert-out":
      if i + 1 >= args.len: stderr.writeLine("Error: --cert-out needs a path"); return 2
      inc i; certOut = args[i]
    of "-h", "--help": printUsage(); return 0
    else:
      stderr.writeLine("Unknown option for `keygen`: ", args[i]); return 2
    inc i

  if opts.sanDnsNames.len == 0: opts.sanDnsNames = @[opts.commonName]

  let res = mintSelfSigned(opts)
  if not res.isOk:
    stderr.writeLine(prettyErr(res.err))
    return 1

  let b = res.val
  if keyOut.len > 0:
    writeFile(keyOut, b.privateKeyPem)
    echo "Wrote private key:  ", keyOut
  if certOut.len > 0:
    writeFile(certOut, b.certificatePem)
    echo "Wrote certificate:  ", certOut

  if keyOut.len == 0 and certOut.len == 0:
    echo b.certificatePem
    echo b.privateKeyPem
  else:
    echo "Subject:            ", b.certInfo.subject
    echo "SAN DNS:            ", b.certInfo.sanDnsNames.join(", ")
    echo "Valid Until:        ", b.certInfo.notAfter
    echo "SHA-256:            ", b.certInfo.sha256Fingerprint
  0

proc runCli*(args: seq[string]): int =
  if args.len == 0:
    printUsage()
    return 0
  case args[0]
  of "trust": cmdTrust(args[1 .. ^1])
  of "probe": cmdProbe(args[1 .. ^1])
  of "fetch": cmdFetch(args[1 .. ^1])
  of "keygen": cmdKeygen(args[1 .. ^1])
  of "version", "--version", "-v": cmdVersion()
  of "help", "--help", "-h": printUsage(); 0
  else:
    stderr.writeLine("Unknown command: ", args[0])
    printUsage()
    2

when isMainModule:
  quit(runCli(commandLineParams()))
