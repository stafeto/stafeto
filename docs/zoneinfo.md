# Time zones

The C library has no time zone database inside the programs. `localtime`,
`mktime`, `tzset` and `strftime` read the zone named by `TZ` from a TZif file
of `/usr/share/zoneinfo` (RFC 9636: the 64-bit transitions of the file, then
the rule of its footer for the years after the last transition). The value
`TZ=:name` and an absolute path work the same way. A name with no file is read
as a POSIX rule (`EST5EDT`, `CET-1CEST,M3.5.0,M10.5.0/3`), and `UTC` (or an
empty `TZ`) needs no file. Any other name gives UTC.

The shell image carries UTC and ten common zones:

| File | Zone |
| --- | --- |
| `Etc/UTC` | UTC |
| `Europe/London`, `Europe/Berlin`, `Europe/Moscow` | Europe |
| `America/New_York`, `America/Chicago`, `America/Los_Angeles` | North America |
| `Asia/Tokyo`, `Asia/Kolkata` | Asia |
| `Australia/Sydney` | Australia |

The files are in `xtask/zoneinfo/` and are built into the image by
`xtask/src/rootfs.rs`. They are the output of `zic -b slim` over the sources of
tzdata 2026e (`https://data.iana.org/time-zones/releases/tzdata2026e.tar.gz`,
SHA-256 `b26882805f26aac59d5b222978e6580484b834ccdc98be89df2f05a6dc53a652`):

```sh
zic -b slim -d out etcetera europe northamerica asia australasia backward
```

To add a zone, compile it the same way, copy its file under
`xtask/zoneinfo/<Region>/<City>` and add it to `ZONES` in `rootfs.rs`. The
data of tzdata is in the public domain.
