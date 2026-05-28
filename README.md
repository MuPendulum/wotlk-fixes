# client-patcher

A simple binary patcher for client version 3.3.5a (build 12340).\
Configure which patches to apply in `config.ini`, then run against your executable.

## Usage

```
client-patcher <file-path>
```

## Configuration

All keys are under `[Patches]` in `config.ini` and accept `true` or `false`.

| Key                | Description                                                    |
|--------------------|----------------------------------------------------------------|
| LargeAddressAware  | Enables the Large Address Aware flag.                          |
| RCEFixes           | Patches known remote code execution vulnerabilities.           |
| WoWFix335          | Miscellaneous gameplay and rendering fixes.                    |
| WoWFix335MailFix   | Removes the 60-second wait before new mail appears.            |
| UpdatePEChecksum   | Recomputes the PE checksum.                                    |

## Building

```
cargo build --release
```

## Credits

- [robinsch](https://github.com/robinsch) — RCE fixes & WoWFix335
