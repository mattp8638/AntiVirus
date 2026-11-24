# Third-party components

Every dependency shipped in a Fenrir-Backup binary or in the web UI, with its licence.
Policy: only permissive licences (MIT, Apache-2.0, BSD, 0BSD, ISC, Zlib, CC0,
Unicode, CDLA-Permissive) are allowed in the Rust crates and the UI; copyleft components
need explicit approval and may only be used by `recovery-env` (which assembles a
Debian-based image and keeps its own manifest). CI enforces the Rust side with
`cargo deny` (`deny.toml`). Where a crate offers a choice of licences,
Fenrir-Backup uses it under the permissive option.

Regenerate the Rust tables with `scripts/third-party.py` after changing dependencies.

## Rust: notable direct dependencies

| Crate | Version | Licence | Used for |
|---|---|---|---|
| aes-gcm | 0.10.3 | Apache-2.0 OR MIT | Sealed secrets (AES-256-GCM) |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | Error handling in binaries |
| argon2 | 0.5.3 | MIT OR Apache-2.0 | Passphrase and administrator password hashing (Argon2id) |
| rustls-pki-types | 1.16.0 | MIT OR Apache-2.0 | Reading the server certificate (PEM) |
| base64 | 0.22.1 | MIT OR Apache-2.0 | Base64 in JSON |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | Keyed chunk hashing, subkey derivation (bundles BLAKE3 C/asm, CC0/Apache-2.0) |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT | XChaCha20-Poly1305 AEAD |
| clap | 4.6.9 | MIT OR Apache-2.0 | Command-line parsing |
| crc32fast | 1.5.5 | MIT OR Apache-2.0 | GPT CRC32 |
| ed25519-dalek | 2.2.0 | BSD-3-Clause | Manifest signatures |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | OS random numbers |
| ext4-view | 1.0.0 | MIT OR Apache-2.0 | Reading ext2/3/4 volumes inside images (file restore) |
| fatfs | 0.3.6 | MIT | Adding the fallback UEFI boot loader to a restored EFI system partition |
| hex | 0.4.3 | MIT OR Apache-2.0 | Hex encoding |
| hkdf | 0.12.4 | MIT OR Apache-2.0 | Sealed secrets key derivation |
| libc | 0.2.191 | MIT OR Apache-2.0 | Linux block-device ioctls |
| ntfs | 0.4.0 | MIT OR Apache-2.0 | Reading NTFS volumes inside images (file restore) |
| ring | 0.17.14 | Apache-2.0 AND ISC | Cryptographic primitives for rustls (Apache-2.0 AND ISC) |
| rpassword | 7.5.5 | Apache-2.0 | Passphrase prompt without echo |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS (server and agent) |
| serde | 1.0.229 | MIT OR Apache-2.0 | Serialisation |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | JSON |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | SHA-256 |
| hmac | 0.12.1 | MIT OR Apache-2.0 | HMAC-SHA256 for S3 request signing (AWS Signature Version 4) |
| md-5 | 0.10.6 | MIT OR Apache-2.0 | Content-MD5 header S3 requires for Object Lock uploads (not used for security) |
| thiserror | 1.0.69 | MIT OR Apache-2.0 | Error types |
| ureq | 2.12.1 | MIT OR Apache-2.0 | Agent HTTPS client |
| uuid | 1.29.3 | Apache-2.0 OR MIT | Identifiers |
| webpki-roots | 0.26.11 | CDLA-Permissive-2.0 | Mozilla CA roots for agents talking to CA-signed servers (CDLA-Permissive-2.0) |
| windows | 0.62.2 | MIT OR Apache-2.0 | Win32/COM bindings (VSS, IOCTLs, registry, DPAPI) |
| windows-service | 0.8.1 | MIT OR Apache-2.0 | Windows service entry point |
| x25519-dalek | 2.0.1 | BSD-3-Clause | Agent key pairs for sealed secrets |
| zeroize | 1.9.2 | Apache-2.0 OR MIT | Wiping key material |
| zstd | 0.13.5 | BSD-3-Clause | zstd compression |
| zstd-safe | 7.4.1 | BSD-3-Clause | zstd binding layer |
| zstd-sys | 2.1.3+zstd.1.5.7 | BSD-3-Clause AND BSD-2-Clause | Bundled zstd C library (BSD-3-Clause) |
| boreal | 1.4 | MIT OR Apache-2.0 | YARA rules in malware scans of backups (`scan`) |

## Web UI (`ui/`)

| Package | Licence | Used for |
|---|---|---|
| react, react-dom | MIT | UI framework |
| lucide-react | ISC | Icons |
| vite, @vitejs/plugin-react | MIT | Build tool (not shipped) |
| typescript, @types/react, @types/react-dom | Apache-2.0 / MIT | Type checking (not shipped) |

Versions are pinned in `ui/package-lock.json`.

## Rust: all crates linked into release binaries (direct and transitive, all targets)

| Crate | Version | Licence |
|---|---|---|
| aead | 0.5.2 | MIT OR Apache-2.0 |
| aes | 0.8.4 | MIT OR Apache-2.0 |
| aes-gcm | 0.10.3 | Apache-2.0 OR MIT |
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.104 | MIT OR Apache-2.0 |
| argon2 | 0.5.3 | MIT OR Apache-2.0 |
| array-init | 2.1.0 | MIT OR Apache-2.0 |
| arrayvec | 0.7.8 | MIT OR Apache-2.0 |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| binrw | 0.11.3 | MIT |
| binrw_derive | 0.11.3 | MIT |
| bitflags | 1.3.2 | MIT/Apache-2.0 |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| blake2 | 0.10.6 | MIT OR Apache-2.0 |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| boreal | 1.4.0 | MIT OR Apache-2.0 |
| boreal-parser | 1.2.0 | MIT OR Apache-2.0 |
| bumpalo | 3.20.4 | MIT OR Apache-2.0 |
| bytemuck | 1.25.2 | Zlib OR Apache-2.0 OR MIT |
| byteorder | 1.5.0 | Unlicense OR MIT |
| cc | 1.11.3 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| chacha20 | 0.9.1 | Apache-2.0 OR MIT |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT |
| cipher | 0.4.4 | MIT OR Apache-2.0 |
| clap | 4.6.9 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.9 | MIT OR Apache-2.0 |
| clap_lex | 1.1.2 | MIT OR Apache-2.0 |
| codespan-reporting | 0.13.1 | Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| convert_case | 0.4.0 | MIT |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| crc | 3.4.0 | MIT OR Apache-2.0 |
| crc-catalog | 2.5.0 | MIT OR Apache-2.0 |
| crc32fast | 1.5.5 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| ctr | 0.9.2 | MIT OR Apache-2.0 |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| der | 0.7.10 | Apache-2.0 OR MIT |
| deranged | 0.5.9 | MIT OR Apache-2.0 |
| derive_more | 0.99.20 | MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| either | 1.19.0 | MIT OR Apache-2.0 |
| enumn | 0.1.14 | MIT OR Apache-2.0 |
| errno | 0.3.15 | MIT OR Apache-2.0 |
| ext4-view | 1.0.0 | MIT OR Apache-2.0 |
| fastrand | 2.5.0 | Apache-2.0 OR MIT |
| fatfs | 0.3.6 | MIT |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| find-msvc-tools | 0.1.15 | MIT OR Apache-2.0 |
| form_urlencoded | 1.2.3 | MIT OR Apache-2.0 |
| futures-core | 0.3.34 | MIT OR Apache-2.0 |
| futures-task | 0.3.34 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| ghash | 0.5.1 | Apache-2.0 OR MIT |
| heck | 0.4.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| hkdf | 0.12.4 | MIT OR Apache-2.0 |
| hmac | 0.12.1 | MIT OR Apache-2.0 |
| icu_collections | 2.4.0 | Unicode-3.0 |
| icu_locale_core | 2.4.0 | Unicode-3.0 |
| icu_normalizer | 2.4.0 | Unicode-3.0 |
| icu_normalizer_data | 2.4.0 | Unicode-3.0 |
| icu_properties | 2.4.0 | Unicode-3.0 |
| icu_properties_data | 2.4.0 | Unicode-3.0 |
| icu_provider | 2.4.0 | Unicode-3.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT |
| inout | 0.1.4 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itoa | 1.0.19 | MIT OR Apache-2.0 |
| jobserver | 0.1.35 | MIT OR Apache-2.0 |
| js-sys | 0.3.107 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| litemap | 0.8.3 | Unicode-3.0 |
| log | 0.4.35 | MIT OR Apache-2.0 |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| memoffset | 0.9.1 | MIT |
| nom | 8.0.0 | MIT |
| nt-string | 0.1.2 | MIT OR Apache-2.0 |
| ntfs | 0.4.0 | MIT OR Apache-2.0 |
| num-conv | 0.2.2 | MIT OR Apache-2.0 |
| object | 0.40.0 | Apache-2.0 OR MIT |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 |
| password-hash | 0.5.0 | MIT OR Apache-2.0 |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.18 | Apache-2.0 OR MIT |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 |
| poly1305 | 0.8.0 | Apache-2.0 OR MIT |
| polyval | 0.6.2 | Apache-2.0 OR MIT |
| potential_utf | 0.1.6 | Unicode-3.0 |
| powerfmt | 0.2.1 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| regex-automata | 0.4.19 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.12 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rpassword | 7.5.5 | Apache-2.0 |
| rtoolbox | 0.0.6 | Apache-2.0 |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustix | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.16.0 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.17 | ISC |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| slab | 0.4.12 | MIT |
| smallvec | 1.16.6 | MIT OR Apache-2.0 |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| strum_macros | 0.24.3 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 1.0.109 | MIT OR Apache-2.0 |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.10 | MIT OR Apache-2.0 |
| synstructure | 0.14.0 | MIT |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| termcolor | 1.4.1 | Unlicense OR MIT |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 |
| time | 0.3.55 | MIT OR Apache-2.0 |
| time-core | 0.1.9 | MIT OR Apache-2.0 |
| time-macros | 0.2.32 | MIT OR Apache-2.0 |
| tinystr | 0.8.5 | Unicode-3.0 |
| tlsh2 | 1.1.0 | Apache-2.0 OR BSD-3-Clause |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-width | 0.2.3 | MIT OR Apache-2.0 |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| ureq | 2.12.1 | MIT OR Apache-2.0 |
| url | 2.5.9 | MIT OR Apache-2.0 |
| utf8_iter | 1.1.0 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| utf_types | 1.0.0 | Apache-2.0 OR MIT |
| uuid | 1.29.3 | Apache-2.0 OR MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.130 | MIT OR Apache-2.0 |
| webpki-roots | 0.26.11 | CDLA-Permissive-2.0 |
| webpki-roots | 1.0.12 | CDLA-Permissive-2.0 |
| widestring | 1.2.1 | MIT OR Apache-2.0 |
| winapi-util | 0.1.11 | Unlicense OR MIT |
| windows | 0.62.2 | MIT OR Apache-2.0 |
| windows-collections | 0.3.2 | MIT OR Apache-2.0 |
| windows-core | 0.62.2 | MIT OR Apache-2.0 |
| windows-future | 0.3.2 | MIT OR Apache-2.0 |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-numerics | 0.3.1 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-service | 0.8.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows-threading | 0.2.1 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| writeable | 0.6.4 | Unicode-3.0 |
| x25519-dalek | 2.0.1 | BSD-3-Clause |
| yoke | 0.8.4 | Unicode-3.0 |
| yoke-derive | 0.8.4 | Unicode-3.0 |
| zerofrom | 0.1.8 | Unicode-3.0 |
| zerofrom-derive | 0.1.8 | Unicode-3.0 |
| zeroize | 1.9.2 | Apache-2.0 OR MIT |
| zeroize_derive | 1.5.0 | Apache-2.0 OR MIT |
| zerotrie | 0.2.5 | Unicode-3.0 |
| zerovec | 0.11.9 | Unicode-3.0 |
| zerovec-derive | 0.11.7 | Unicode-3.0 |
| zmij | 1.0.23 | MIT |
| zstd | 0.13.5 | BSD-3-Clause |
| zstd-safe | 7.4.1 | BSD-3-Clause |
| zstd-sys | 2.1.3+zstd.1.5.7 | BSD-3-Clause AND BSD-2-Clause |

## Test and development only (not shipped)

| Crate | Licence | Used for |
|---|---|---|
| tempfile | MIT OR Apache-2.0 | Temporary directories in tests |
| qemu-img (system tool, optional) | GPL-2.0 | Independent VHDX interoperability checks in tests; never linked or shipped |
| CirrOS 0.6.2 disk image (downloaded in CI) | GPL-2.0 (kernel, BusyBox) and others | Bootable test guest for boot-from-backup tests; never shipped |
| tower, http-body-util | MIT | In-process server API tests |
| libfuzzer-sys | (MIT OR Apache-2.0) AND NCSA | Fuzzing harness (`fuzz/`) |
| playwright (pre-installed) | Apache-2.0 | UI end-to-end checks during development |

## Platform interfaces

* Windows: Volume Shadow Copy Service, Hyper-V WMI (`root\virtualization\v2`),
  DeviceIoControl, registry, DPAPI and firmware APIs are called through their
  documented public interfaces. The `IVssBackupComponents` vtable layout follows
  the public Windows SDK header `vsbackup.h`. The VHDX reader is implemented from
  Microsoft's published Open Specification [MS-VHDX]. No Microsoft code is
  redistributed.
* Linux: kernel ioctls (`BLKSSZGET`, `BLKPBSZGET`), `/proc`, `/sys`.
* Network share repositories: on Windows through the documented
  `WNetAddConnection2W` / `WNetCancelConnection2W` API (mpr.dll); on Linux
  through the system's `mount -t cifs` (cifs-utils, GPL-3.0, installed by
  the administrator and run as a separate program, never linked or shipped).
* Boot from backup: the agent starts the host's own `qemu-system-x86_64` and
  `qemu-img` (GPL-2.0) and OVMF firmware (BSD-2-Clause-Patent) as separate
  programs, installed by the administrator from the distribution; nothing
  from them is linked into or shipped with Fenrir-Backup. They are driven
  through their documented command-line options, QMP (the QEMU Machine
  Protocol) and the QEMU guest agent protocol. The NBD server implements the
  NBD project's published protocol description. The Hyper-V boot check uses
  the documented `Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage`
  WMI method.
* Live Linux images and growing file systems: the system's own LVM tools
  (`lvs`, `pvs`, `vgs`, `lvcreate`, `lvremove`, `pvresize`; lvm2,
  GPL-2.0/LGPL-2.1), `lsblk`, `fsfreeze`, `losetup`, `blockdev` (util-linux,
  GPL-2.0), `e2fsck`/`resize2fs` (e2fsprogs, GPL-2.0), `ntfsresize`
  (ntfs-3g, GPL-2.0) and on Windows `diskpart`, run as separate programs
  through their documented command lines; nothing from them is linked into
  Fenrir-Backup. The recovery image installs them from Debian.
* macOS: `ioreg`, `sw_vers`, launchd.
