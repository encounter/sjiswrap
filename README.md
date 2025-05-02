# sjiswrap [![Build Status]][actions]

[Build Status]: https://github.com/encounter/sjiswrap/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/encounter/sjiswrap/actions

UTF-8 to Shift JIS wrapper for old 32-bit Windows compilers.

When the wrapped executable reads a text file, it will be encoded from UTF-8 to Shift JIS on the fly.

Encoded file extensions:
- `.c`
- `.cc`
- `.cp`
- `.cpp`
- `.cxx`
- `.h`
- `.hh`
- `.hp`
- `.hpp`
- `.hxx`
- `.inc`

## Usage

Download the latest release from [here](https://github.com/encounter/sjiswrap/releases).

```shell
$ sjiswrap.exe <exe> [args...]
```

## Building

```shell
$ cargo build --target i686-pc-windows-msvc --release
```

For smaller binaries:

```shell
$ cargo +nightly build -Z build-std=std,panic_abort --target i686-pc-windows-msvc --release
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
