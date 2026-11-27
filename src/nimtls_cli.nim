import std/os
import ./nimtls/cli

when isMainModule:
  quit(runCli(commandLineParams()))
