# bootvars

reads uefi variables from windows and decodes `Boot####` load options and their
efi device paths. also parses a captured variable from disk, so the parser is
usable on a box with no firmware access at all.

status: parser and device-path decoding done and self-tested. firmware access
needs uefi + an elevated process; on this machine it returns
`ERROR_PRIVILEGE_NOT_HELD` (0x522), which is what `example/firmware.txt` shows.
signed variable lists (PK/KEK/db) are dumped as bytes, not parsed yet.

TODO: expand this section
```
build.bat
```

```
build\bootvars.exe --selftest
build\bootvars.exe --offline tests\fixtures\boot2.bin
build\bootvars.exe --var Boot0001
build\bootvars.exe --var PK --guid {d719b2cb-3d3a-4596-a3bc-dad00e67656f} --raw
build\bootvars.exe --emit my.bin
```

TODO: expand this section
`--emit` writes the same synthetic `EFI_LOAD_OPTION` the selftest uses, so you
can round-trip it through `--offline`.

```
load option  attrs 0x00000001 [ACTIVE ]
  desc      Windows Boot Manager
  pathlen   116
  [0]      HD(part 1, start 0x800, size 0x0, mbr 2, sig 1, C12A7328-F81F-11D2-BA4B-00A0C93EC93B) (type 04 sub 01 len 42)
  [1]      File(\EFI\Microsoft\Boot\bootmgfw.efi) (type 04 sub 04 len 70)
  [2]      End (type 7F sub FF len 4)
  optional  8 bytes
  0000  57 49 4E 44 4F 57 53 00                          |WINDOWS.|
