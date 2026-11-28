# Lessons

## Editing files from scripts
- Python/bash heredocs mangle C# escapes: `\n` became a real newline in a C# string, `\\\\` in a test lost backslashes.
  Rule: use the Edit/Write tools for any C# text that holds backslashes or `\n`; use scripts only for plain text swaps.
- After any scripted edit, build before committing. A "0 errors" build that ran before the edit proves nothing.

## Test fakes
- Tightening a shared fake (exact WMI class match) broke 26 tests that registered query fragments.
  Rule: check how existing tests call a TestKit fake before changing its matching rules; prefer a stricter-but-compatible rule
  (whole-word) over a breaking one.

## Elevated runs
- UAC prompts can sit hidden behind other windows. When an admin step is pending, check for `consent.exe` and tell the user
  to look for the prompt instead of waiting silently.

## Reports from in-memory scan items
- The items in `ScanRunResult` are NOT redacted (only the DB/JSON copies are). Anything rendered from them must go through
  `Redactor.Redact` before HTML encoding.

## Same mistake twice
- A Python edit of a C# regex silently did nothing (the `\(` escapes did not match) right after writing the rule above.
  Rule: for any line containing a backslash, use the Edit tool, full stop, and grep afterwards to confirm the change landed.

## Running the elevated EXE for testing
- A background launcher "completing" does not mean UAC was approved (bash `&` returns at once). Check for `consent.exe`
  and for the run's own output file before saying the run started.
- `cmd start /wait` reports exit code 0 for a GUI-subsystem EXE whatever it returns; use PowerShell (`& exe ... | Out-File`;
  `$LASTEXITCODE`) to read real exit codes. Windows PowerShell's Out-File writes UTF-16, so `grep` on it finds nothing.
- Read the real report in a browser (headless Edge screenshot) after every report change: the wording contradictions
  (banner vs row labels vs heading) were invisible in unit tests.

## Shell and Python strings are scripted edits too
- A bash heredoc turned a C# char literal of two backslashes into one, and a Python edit of todo.md died on a backslash
  path. New files go through Write and edits through Edit whenever a backslash is involved, including docs.

## Fixtures find what unit tests miss
- The tier-3 fake drive found two bugs on its first run that 750 unit tests missed, because it runs the REAL signature
  checker and the REAL case.db together. When a rule depends on two components (signature status x path rules, item
  key x database primary key), test them together at least once.

## Port, don't approximate
- The winget name matcher was "close to winget's rules" and missed real cases (s.r.o., Build 3211, brackets). Porting
  winget's actual regexes and checking them against winget's own 1,137 test cases matched 100% on the first run.
  When a project mirrors another tool's behaviour, fetch that tool's source and test data instead of guessing.
- Python heredocs with Windows paths fail too (\U escapes). Third time: Edit tool for anything with a backslash.

## Backslashes: fourth time
- A sed edit wrote `scripts\regress.ps1` into a normal C# string, where `\r` is a carriage return. It compiled, so only
  review caught it. Rule, before ANY sed/python/heredoc edit: if the old or new text contains a backslash, stop and
  use Edit/Write. In C# strings, prefer forward slashes in user-facing paths to scripts.

## Scripts that run on the target PC: test them in Windows PowerShell 5.1 (2026-11-27)
- The target PC may only have powershell.exe 5.1. baseline.ps1 worked in pwsh 7 but failed in 5.1 twice:
  "$label:" parses as a drive-qualified variable (use ${label}:), and ConvertFrom-Json in 5.1 rejects a JSON object
  with an empty key "" (pwsh 7 accepts it). Rule: run every shipped script with `powershell.exe -NoProfile -File`
  before packaging; never write empty or null dictionary keys to JSON.

## Check the binary, not just the source, before anything goes public (2026-11-27)
- The source was scrubbed before the repo went public, but the published EXE still held the build folder (Windows user
  name, OneDrive tenant) in five embedded PDB paths. Fixed with PathMap in Directory.Build.props. Rule: before
  publishing a release, search the EXE's bytes (ASCII and UTF-16) for the user name, tenant and machine name.

## Timing tests measure from the event, not from the start (2026-11-27)
- A "stops within 2 s of Cancel" test started its stopwatch before the work began, so shell start-up under the full
  parallel test run (2.6 s) failed it. Rule: in latency tests, record the moment the trigger fires (token.Register)
  and assert on the time after it; and never trust a sub-agent's "ALL PASSED": rerun it.

## PowerShell array literals and + (2026-11-27)
- In `@('a' + "b", 'c')` the comma binds before `+`, so string concatenation inside an array literal silently builds
  the wrong list. It mangled three template edits during the gap-closure work. Rule: build strings first (or wrap each
  element in parentheses), and never edit templates through PowerShell string building; use Edit/Write.

## Never hand attacker-controlled side files to SQLite (2026-11-27)
- DbSnapshot copied a browser's `-journal` next to its copy and opened the copy read-write. SQLite rolls back a hot
  journal, and a journal's super-journal name makes SQLite DELETE that file: an infected old drive could delete any
  file with admin rights. Rule: copy only the database and `-wal`; never `-journal`; prefer `immutable=1`/read-only
  opens for untrusted databases. And a security test must fail before the fix: the first version passed because SQLite
  silently deleted the junk journal, so assert on what PCPorter reads (SourceFiles.Observe), not on what is left.
