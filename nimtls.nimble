# Package

version       = "0.3.0"
author        = "Abhradeep Basak <abhradeepbasak07@gmail.com>"
description   = "Static BearSSL TLS, tiered OS/embedded CA trust store, Sans-I/O engine, HTTP fetch, C-ABI, and readable TLS errors for Nim"
license       = "MIT"
srcDir        = "src"
installDirs   = @["nimtls"]
namedBin      = {"nimtls_cli": "nimtls"}.toTable

# Dependencies

requires "nim >= 2.0.0"

# Tasks

task test, "Run all Nim tests":
  exec "nim c -r --hints:off tests/test_errors.nim"
  exec "nim c -r --hints:off -d:nimtlsEmbedRoots tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_truststore.nim"
  exec "nim c -r --hints:off tests/test_x509_keygen.nim"
  exec "nim c -r --hints:off -d:nimtlsEmbedRoots tests/test_engine_loopback.nim"
  exec "nim c -r --hints:off -d:nimtlsEmbedRoots --threads:on tests/test_client_async.nim"

task buildCli, "Build standalone nimtls CLI with embedded Mozilla roots":
  exec "nim c -d:release -d:nimtlsEmbedRoots -o:nimtls src/nimtls_cli.nim"

task examples, "Compile-check all standalone examples":
  exec "nim c --hints:off -d:nimtlsEmbedRoots examples/fetch_https.nim"
  exec "nim c --hints:off -d:nimtlsEmbedRoots examples/async_fetch.nim"
  exec "nim c --hints:off -d:nimtlsEmbedRoots examples/local_https_server.nim"
  exec "nim c --hints:off -d:nimtlsEmbedRoots examples/sans_io_mem.nim"
