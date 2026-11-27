# Package

version       = "0.2.0"
author        = "Abhradeep Basak"
description   = "Static BearSSL TLS, tiered OS/embedded CA trust store, Sans-I/O engine, HTTP fetch, C-ABI, and readable TLS errors for Nim"
license       = "MIT"
srcDir        = "src"
installDirs   = @["nimvault"]
namedBin      = {"nimvault_cli": "nimvault"}.toTable

# Dependencies

requires "nim >= 2.0.0"

# Tasks

task test, "Run all Nim tests":
  exec "nim c -r --hints:off tests/test_errors.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_x509_keygen.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_engine_loopback.nim"
  exec "nim c -r --hints:off -d:nimvaultEmbedRoots --threads:on tests/test_client_async.nim"

task buildCli, "Build standalone nimvault CLI with embedded Mozilla roots":
  exec "nim c -d:release -d:nimvaultEmbedRoots -o:nimvault src/nimvault_cli.nim"

task examples, "Compile-check all standalone examples":
  exec "nim c --hints:off -d:nimvaultEmbedRoots examples/fetch_https.nim"
  exec "nim c --hints:off -d:nimvaultEmbedRoots examples/async_fetch.nim"
  exec "nim c --hints:off -d:nimvaultEmbedRoots examples/local_https_server.nim"
  exec "nim c --hints:off -d:nimvaultEmbedRoots examples/sans_io_mem.nim"
