# Package

version       = "0.1.0"
author        = "Abhradeep Basak"
description   = "Zero-dependency static TLS, tiered OS/embedded trust store, Sans-I/O engine, C-ABI, and actionable TLS diagnostics for Nim"
license       = "MIT"
srcDir        = "src"
installDirs   = @["nimvault", "../vendor", "../include"]
namedBin      = {"nimvault_cli": "nimvault"}.toTable

# Dependencies

requires "nim >= 2.0.0"

# Tasks

task test, "Run all Nim unit and loopback TLS tests":
  exec "nim c -r --hints:off tests/test_errors.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_x509_keygen.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_engine_loopback.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots --threads:on tests/test_client_async.nim"

task buildCli, "Build standalone nimvault CLI binary with embedded roots":
  exec "nim c -d:release -d:nimvaultEmbedRoots -o:nimvault src/nimvault_cli.nim"
