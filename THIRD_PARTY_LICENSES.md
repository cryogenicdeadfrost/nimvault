# Third-Party Licenses

`nimtls` bundles two third-party components inside `src/nimtls/vendor/` so users don't need CMake or system OpenSSL:

## BearSSL (v0.6)
- **Location:** `src/nimtls/vendor/bearssl/`
- **Homepage:** https://bearssl.org/
- **License:** MIT License
- **Copyright:** Copyright (c) 2016-2018 Thomas Pornin <pornin@bolet.org>
- Full license text: `src/nimtls/vendor/bearssl/LICENSE.txt`

## Mozilla CA Certificate Store (via curl.se)
- **Location:** `src/nimtls/vendor/cacert.pem`
- **Source:** https://curl.se/ca/cacert.pem (extracted from Mozilla NSS `certdata.txt`)
- **License:** Mozilla Public License 2.0 (MPL-2.0)
- **URL:** https://www.mozilla.org/en-US/MPL/2.0/

