# ownmesh-logs

Log providers and cursor-based queries sharing one contract:

`LogCursor { provider, offset }` + `limit` → `LogPage { lines, next_cursor, exhausted }`.

## Built-in providers

| Id | Backend | Availability |
|---|---|---|
| file / audit | local file byte offset | all OS |
| windows_event | `wevtutil qe` (Windows Event Log) | Windows (live) |
| journald | `journalctl` / sd-journal data plane | Linux native; Unavailable stub elsewhere |
| docker | `docker logs` / `podman logs` | all OS when runtime present |
| process | process stdout/stderr spool file | all OS |

## References

- Windows Event Log: https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log
- wevtutil: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
- sd-journal: https://www.freedesktop.org/software/systemd/man/latest/sd-journal.html
- journalctl(1): https://www.man7.org/linux/man-pages/man1/journalctl.1.html
