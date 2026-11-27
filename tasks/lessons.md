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
