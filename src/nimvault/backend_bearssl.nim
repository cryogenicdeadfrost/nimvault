# Low-level FFI to our static BearSSL 0.6 C shim (zero OpenSSL, zero CMake).

import std/strutils
import ./private/bearssl_sources
export bearssl_sources

const
  BR_SSL_CLOSED*  = 0x0001'u32
  BR_SSL_SENDREC* = 0x0002'u32
  BR_SSL_RECVREC* = 0x0004'u32
  BR_SSL_SENDAPP* = 0x0008'u32
  BR_SSL_RECVAPP* = 0x0010'u32

  BR_TLS10* = 0x0301'u32
  BR_TLS11* = 0x0302'u32
  BR_TLS12* = 0x0303'u32

type
  NvEngineHandle* = pointer

proc nv_engine_free*(e: NvEngineHandle) {.importc, cdecl.}

proc nv_client_create*(
  serverName: cstring,
  caPem: cstring,
  caPemLen: csize_t,
  insecureSkipVerify: cint,
  versionMin: cuint,
  versionMax: cuint,
  alpn: ptr cstring,
  alpnCount: csize_t,
  failOnAlpnMismatch: cint,
  validationTimeUnix: uint64,
  outTaCount: ptr cint,
  outErr: ptr cint
): NvEngineHandle {.importc, cdecl.}

proc nv_server_create*(
  certPem: cstring,
  certPemLen: csize_t,
  keyPem: cstring,
  keyPemLen: csize_t,
  versionMin: cuint,
  versionMax: cuint,
  alpn: ptr cstring,
  alpnCount: csize_t,
  failOnAlpnMismatch: cint,
  outErr: ptr cint
): NvEngineHandle {.importc, cdecl.}

proc nv_engine_state*(e: NvEngineHandle): cuint {.importc, cdecl.}
proc nv_engine_last_error*(e: NvEngineHandle): cint {.importc, cdecl.}

proc nv_engine_feed_encrypted*(e: NvEngineHandle, data: ptr byte, len: csize_t): csize_t {.importc, cdecl.}
proc nv_engine_drain_encrypted*(e: NvEngineHandle, dest: ptr byte, cap: csize_t): csize_t {.importc, cdecl.}
proc nv_engine_write_plaintext*(e: NvEngineHandle, data: ptr byte, len: csize_t): csize_t {.importc, cdecl.}
proc nv_engine_read_plaintext*(e: NvEngineHandle, dest: ptr byte, cap: csize_t): csize_t {.importc, cdecl.}

proc nv_engine_flush*(e: NvEngineHandle) {.importc, cdecl.}
proc nv_engine_close*(e: NvEngineHandle) {.importc, cdecl.}

proc nv_engine_get_version*(e: NvEngineHandle): cuint {.importc, cdecl.}
proc nv_engine_get_cipher_suite*(e: NvEngineHandle): uint16 {.importc, cdecl.}
proc nv_engine_get_alpn*(e: NvEngineHandle): cstring {.importc, cdecl.}
proc nv_engine_get_server_name*(e: NvEngineHandle): cstring {.importc, cdecl.}
proc nv_engine_get_peer_cert*(e: NvEngineHandle, outLen: ptr csize_t): ptr byte {.importc, cdecl.}
proc nv_engine_get_peer_chain_len*(e: NvEngineHandle): csize_t {.importc, cdecl.}
proc nv_engine_get_x509_error*(e: NvEngineHandle): cuint {.importc, cdecl.}

proc nv_random_bytes*(output: ptr byte, len: csize_t): cint {.importc, cdecl.}

proc nv_ec_keygen_p256*(
  privRaw32: ptr byte,
  privRawLen: ptr csize_t,
  pubUncompressed65: ptr byte,
  pubLen: ptr csize_t,
  pkcs8DerOut: ptr byte,
  pkcs8DerLen: ptr csize_t
): cint {.importc, cdecl.}

proc nv_ecdsa_sign_p256_sha256*(
  privRaw: ptr byte,
  privLen: csize_t,
  hash32: ptr byte,
  sigAsn1Out: ptr byte,
  sigCap: csize_t
): csize_t {.importc, cdecl.}

proc tlsVersionName*(version: uint32): string =
  case version
  of BR_TLS10: "TLS 1.0"
  of BR_TLS11: "TLS 1.1"
  of BR_TLS12: "TLS 1.2"
  of 0x0304'u32: "TLS 1.3"
  of 0'u32: "Negotiating"
  else: "Unknown(0x" & toHex(version, 4) & ")"

proc cipherSuiteName*(suite: uint16): string =
  case suite
  of 0xCCA8'u16: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
  of 0xCCA9'u16: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
  of 0xC02F'u16: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  of 0xC030'u16: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  of 0xC02B'u16: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
  of 0xC02C'u16: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  of 0xC027'u16: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
  of 0xC028'u16: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
  of 0xC023'u16: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
  of 0xC024'u16: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
  of 0xC013'u16: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
  of 0xC014'u16: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
  of 0xC009'u16: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
  of 0xC00A'u16: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
  of 0x009C'u16: "TLS_RSA_WITH_AES_128_GCM_SHA256"
  of 0x009D'u16: "TLS_RSA_WITH_AES_256_GCM_SHA384"
  of 0x003C'u16: "TLS_RSA_WITH_AES_128_CBC_SHA256"
  of 0x003D'u16: "TLS_RSA_WITH_AES_256_CBC_SHA256"
  of 0x002F'u16: "TLS_RSA_WITH_AES_128_CBC_SHA"
  of 0x0035'u16: "TLS_RSA_WITH_AES_256_CBC_SHA"
  of 0x0000'u16: "NONE"
  else: "CIPHER_0x" & toHex(suite, 4)
