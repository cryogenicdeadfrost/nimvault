## nimvault CLI: `trust`, `probe`, `keygen`, and `version` commands.

import std/[strutils, json]
import ./errors
import ./truststore
import ./x509
import ./engine
import ./client
import ./keygen

const NimvaultVersion* = "0.1.0"

proc printUsage() =
  echo """nimvault """ & NimvaultVersion & """ — Zero-dependency static TLS & trust diagnostics (BearSSL 0.6)

Usage:
  nimvault trust   [options]             Inspect tiered CA trust store resolution
  nimvault probe   <host[:port]> [opts]  Connect over static TLS & inspect peer/errors
  nimvault keygen  [options]             Generate ECDSA P-256 key + self-signed X.509 v3 cert
  nimvault version                       Show version and compile-time backend info

Trust options:
  --ca-file <path>      Validate a specific PEM CA bundle file
  --no-embedded         Disable embedded Mozilla roots fallback
  --json                Output machine-readable JSON

Probe options:
  --port <num>          Target port (default: 443)
  --sni <hostname>      Override SNI / verification hostname
  --ca-file <path>      Use a custom PEM CA bundle
  --alpn <proto>        Offer ALPN protocol (repeatable, e.g. --alpn http/1.1)
  --timeout <ms>        Socket timeout in milliseconds (default: 10000)
  --insecure            Skip X.509 chain verification (inspection/debugging only)
  --json                Output machine-readable JSON

Keygen options:
  --cn <name>           Common Name (default: localhost)
  --org <name>          Organization name (default: nimvault-dev)
  --san <dns>           Subject Alternative Name DNS entry (repeatable)
  --days <num>          Validity duration in days (default: 365)
  --key-out <path>      Write PKCS#8 private key PEM to file
  --cert-out <path>     Write X.509 certificate PEM to file"""

proc cmdVersion(): int =
  echo "nimvault ", NimvaultVersion
  echo "  TLS Backend:     BearSSL 0.6 (statically vendored, zero OpenSSL)"
  echo "  TLS Versions:    TLS 1.0 - TLS 1.2 (AEAD: AES-GCM, ChaCha20-Poly1305)"
  echo "  Embedded Roots:  ", (if hasEmbeddedRoots(): "enabled (Mozilla CA bundle compiled in)" else: "disabled (compile with -d:nimvaultEmbedRoots)")
  0

proc cmdTrust(args: seq[string]): int =
  var caFile = ""
  var allowEmbedded = true
  var jsonOut = false

  var i = 0
  while i < args.len:
    case args[i]
    of "--ca-file":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --ca-file requires a path")
        return 2
      inc i
      caFile = args[i]
    of "--no-embedded":
      allowEmbedded = false
    of "--json":
      jsonOut = true
    of "-h", "--help":
      printUsage()
      return 0
    else:
      stderr.writeLine("Unknown option for `trust`: ", args[i])
      return 2
    inc i

  let res = resolveTrustStore(explicitPath = caFile, allowEmbeddedFallback = allowEmbedded)
  if not res.isOk:
    if jsonOut:
      let j = %*{
        "ok": false,
        "embeddedRootsAvailable": hasEmbeddedRoots(),
        "error": {
          "kind": $res.err.kind,
          "message": res.err.message,
          "likelyCause": res.err.likelyCause,
          "suggestion": res.err.suggestion
        }
      }
      echo j.pretty()
    else:
      stderr.writeLine(formatDiagnostic(res.err))
    return 1

  let b = res.val
  if jsonOut:
    let j = %*{
      "ok": true,
      "sourceKind": $b.sourceKind,
      "sourcePath": b.sourcePath,
      "certCount": b.certCount,
      "pemBytes": b.pemData.len,
      "embeddedRootsAvailable": hasEmbeddedRoots()
    }
    echo j.pretty()
  else:
    echo "Trust Store Resolution: OK"
    echo "  Source Kind:     ", b.sourceKind
    echo "  Source Path:     ", b.sourcePath
    echo "  Certificates:    ", b.certCount
    echo "  PEM Size:        ", b.pemData.len, " bytes"
    echo "  Embedded Roots:  ", (if hasEmbeddedRoots(): "compiled in" else: "not compiled in")
  0

proc parseHostPort(target: string, defaultPort: int): tuple[host: string, port: int] =
  var clean = target.strip()
  if clean.startsWith("https://"):
    clean = clean[8 .. ^1]
  elif clean.startsWith("http://"):
    clean = clean[7 .. ^1]
  let slash = clean.find('/')
  if slash >= 0:
    clean = clean[0 ..< slash]
  let colon = clean.rfind(':')
  if colon > 0 and not clean.endsWith("]"):
    try:
      return (clean[0 ..< colon], parseInt(clean[colon + 1 .. ^1]))
    except ValueError:
      discard
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
      if i + 1 >= args.len:
        stderr.writeLine("Error: --port requires a number")
        return 2
      inc i
      portOverride = parseInt(args[i])
    of "--sni":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --sni requires a hostname")
        return 2
      inc i
      sni = args[i]
    of "--ca-file":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --ca-file requires a path")
        return 2
      inc i
      caFile = args[i]
    of "--alpn":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --alpn requires a protocol name")
        return 2
      inc i
      alpn.add(args[i])
    of "--timeout":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --timeout requires milliseconds")
        return 2
      inc i
      timeoutMs = parseInt(args[i])
    of "--insecure":
      insecure = true
    of "--json":
      jsonOut = true
    of "-h", "--help":
      printUsage()
      return 0
    else:
      if args[i].startsWith("-"):
        stderr.writeLine("Unknown option for `probe`: ", args[i])
        return 2
      if target.len == 0:
        target = args[i]
      else:
        stderr.writeLine("Unexpected extra argument: ", args[i])
        return 2
    inc i

  if target.len == 0:
    stderr.writeLine("Usage: nimvault probe <host[:port]> [options]")
    return 2

  var (host, port) = parseHostPort(target, 443)
  if portOverride > 0:
    port = portOverride

  var cfg = defaultTlsConfig(if sni.len > 0: sni else: host)
  cfg.caBundlePath = caFile
  cfg.insecureSkipVerify = insecure
  if alpn.len > 0:
    cfg.alpnProtocols = alpn
  else:
    cfg.alpnProtocols = @["http/1.1"]

  let rep = probe(host, port, cfg, timeoutMs)

  if jsonOut:
    var certObj = newJNull()
    if rep.peerInfo.hasPeerCert:
      let c = rep.peerInfo.peerCert
      certObj = %*{
        "version": c.version,
        "subject": c.subject,
        "subjectCN": c.subjectCN,
        "issuer": c.issuer,
        "issuerCN": c.issuerCN,
        "notBefore": c.notBefore,
        "notAfter": c.notAfter,
        "sanDnsNames": c.sanDnsNames,
        "sanIps": c.sanIps,
        "keyAlgorithm": c.keyAlgorithm,
        "sigAlgorithm": c.sigAlgorithm,
        "sha256Fingerprint": c.sha256Fingerprint
      }
    var errObj = newJNull()
    if not rep.success:
      errObj = %*{
        "kind": $rep.error.kind,
        "code": rep.error.code,
        "alertCode": rep.error.alertCode,
        "message": rep.error.message,
        "likelyCause": rep.error.likelyCause,
        "suggestion": rep.error.suggestion
      }
    let j = %*{
      "host": rep.host,
      "port": rep.port,
      "success": rep.success,
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
    }
    echo j.pretty()
    return if rep.success: 0 else: 1

  echo "TLS Probe: ", rep.host, ":", rep.port
  echo "  Status:          ", (if rep.success: "OK (Handshake succeeded)" else: "FAILED")
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
    if c.sanDnsNames.len > 0:
      echo "    SAN DNS:       ", c.sanDnsNames.join(", ")
    echo "    SHA-256:       ", c.sha256Fingerprint

  if not rep.success:
    echo ""
    stderr.writeLine(formatDiagnostic(rep.error))
    return 1
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
      if i + 1 >= args.len:
        stderr.writeLine("Error: --cn requires a value")
        return 2
      inc i
      opts.commonName = args[i]
    of "--org":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --org requires a value")
        return 2
      inc i
      opts.organization = args[i]
    of "--san":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --san requires a DNS name")
        return 2
      inc i
      opts.sanDnsNames.add(args[i])
    of "--days":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --days requires a number")
        return 2
      inc i
      opts.validDays = parseInt(args[i])
    of "--key-out":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --key-out requires a file path")
        return 2
      inc i
      keyOut = args[i]
    of "--cert-out":
      if i + 1 >= args.len:
        stderr.writeLine("Error: --cert-out requires a file path")
        return 2
      inc i
      certOut = args[i]
    of "-h", "--help":
      printUsage()
      return 0
    else:
      stderr.writeLine("Unknown option for `keygen`: ", args[i])
      return 2
    inc i

  if opts.sanDnsNames.len == 0:
    opts.sanDnsNames = @[opts.commonName]

  let res = generateSelfSignedEcP256(opts)
  if not res.isOk:
    stderr.writeLine(formatDiagnostic(res.err))
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
  of "keygen": cmdKeygen(args[1 .. ^1])
  of "version", "--version", "-v": cmdVersion()
  of "help", "--help", "-h":
    printUsage()
    0
  else:
    stderr.writeLine("Unknown command: ", args[0])
    printUsage()
    2
