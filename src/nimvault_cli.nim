import std/os
import ./nimvault/cli

when isMainModule:
  quit(runCli(commandLineParams()))
