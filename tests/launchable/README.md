# Compiled launch fixture

This is the source-build phase of issue #313. The original freestanding C
fixture generates 60 frames' worth of guest-local pixel data and prepares
an exit status. Connecting those writes to the guest graphics bridge and
executing the fixture are separate steps gated on #159, #316 and #317.

From the repository root, with native Rust on PATH and the Xcode command
line tools installed, run:

```sh
/usr/bin/python3 tests/launchable/build.py --verify-reproducible
```

The reproducibility check builds twice in fresh directories and compares all
four executable hashes and header listings before publishing outputs. The build
also rejects identical outputs from different variants. All compiles use
the same captured source bytes, which are hashed in the build receipt.

The recipe defaults to Xcode clang and the active Rust toolchain's
`rust-lld`. It records concrete versions, ARM64 tool evidence, compiler
and linker options, the definitions for each variant, source and output
hashes, and PE section and directory
facts. It also saves LLVM PE header listings, checks the exact DLL and
symbol imports for each variant, and requires an empty base relocation
directory for this source. The baseline build used Apple clang 21.0.0 (clang-2100.1.1.101)
and rust-lld 23.1.5 (0a5579eb). `CLANG` and `LLD_LINK` may point to
alternative native tools. The import library is generated locally from
source-authored declarations. Build outputs go under ignored `artifacts/`
by default.

| Variant | Expected runtime result once integrated |
| --- | --- |
| `launch.exe` | Finish frame 59 and exit with `0x4C4E4348` |
| `missing-import.exe` | Reject `LaunchMissingFixtureImport` before entry |
| `wrong-expectation.exe` | Finish frame 59 and exit with status 1 |
| `exhaust.exe` | Exceed the instruction budget before finishing frame zero |

Use the draft frame proposal from #321 for contract coordination. The first
30 frames contain RGBA (255, 128, 0, 255) at every pixel. The next 30 use
(64x, 96y, 255 − 64x, 255) for integer x from 0 to 3 and y from 0 to 2.
For example, pixel (3, 2) changes from (255, 128, 0, 255) to
(192, 192, 63, 255). The top-left origin and submission contract await
agreement in #159.

Each output is AMD64 PE32+ with an entry point and an import table. The
initial source uses no absolute data pointers requiring a base relocation.
Static inspection with `xcrun llvm-objdump -p` shows that the main executable
imports `ExitProcess` and the missing-import control adds
`LaunchMissingFixtureImport`. Execution admission, observed guest exit,
and rendering evidence remain pending.

References: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).
