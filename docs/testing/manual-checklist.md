# PCPorter manual GUI checklist (tier 6)

Plan: [docs/plans/2026-11-26-regression-testing.md](../plans/2026-11-26-regression-testing.md). Run this before
handing a new build to another PC, after `scripts/regress.ps1 -Level release` has passed. It covers what the
automated tiers can't: the windows themselves. About 20 minutes. Automating it with FlaUI is planned for Phase 7.

Use the packaged EXE (`C:\PCPorter-dist\PCPorter\PCPorter.exe`), not a debug build. Write results to
`C:\PCPorterCases\manual\` (never OneDrive). Copy the table at the end into the release notes or `tasks/todo.md`.

## Setup
- [ ] Fake old-PC drive: `.\scripts\regress.ps1 -Level release` leaves the fixture at
      `C:\PCPorterCases\regress\fixture-oldpc`. Give it a drive letter so the app lists it as another PC's drive:
      `subst P: C:\PCPorterCases\regress\fixture-oldpc`. Remove it afterwards with `subst P: /D`.
- [ ] Optional: a BitLocker-locked drive (a USB stick, or a VHD with BitLocker turned on and then locked).

## 1. Start-up and Home
- [ ] Start PCPorter without administrator rights. The title bar says `PCPorter`. Home shows three tiles.
- [ ] Start it again while it is open: a box says "PCPorter is already running." The first window stays open.
- [ ] Close it. Right-click > Run as administrator. The title says `PCPorter  -  running as administrator`.
- [ ] Click "Move to my new PC": a box says backup and restore are still being built and points to the health check.
- [ ] The light/dark theme follows Windows (switch it in Settings > Personalization > Colors while the app is open).
- [ ] About: the version shows. "Open log folder" opens `C:\ProgramData\PCPorter\logs`.

## 2. Health and security (this PC)
- [ ] The default save folder is a removable drive if one is plugged in, otherwise `C:\PCPorterCases`.
- [ ] Type a OneDrive folder as the save folder and press Start: "Pick another folder" with the cloud-sync reason.
      Nothing is created there.
- [ ] Set the folder to `C:\PCPorterCases\manual`. Start the check.
  - [ ] Cards appear one by one with counts. The elapsed timer runs.
  - [ ] While it runs: the scan choice, folder box, Browse and Start are greyed out. Cancel is enabled.
- [ ] When it ends: a result message, plus "Open the report" and "Open the case folder".
  - [ ] Open the report: it opens in the browser. The banner counts match the labels on the page. The footer says
        "Read-only scan. Nothing was changed".
  - [ ] Open the case folder: it holds HealthReport.html, case.db and a scan folder. Properties > Security lists only
        SYSTEM, Administrators and you.
- [ ] Start again and press Cancel during the second or third card. The message turns amber: "Stopped". The report
      that opens shows what was checked so far. The controls are enabled again.

## 3. Health and security (another PC's drive)
- [ ] Choose "Another PC's drive" and press Refresh. `P:\` appears in the list.
- [ ] Set the save folder to `P:\out` and press Start: "Pick another folder" (results can't go on the drive being
      checked). Nothing is created on `P:`.
- [ ] Save to `C:\PCPorterCases\manual` instead and run it. The report names OLDPC and Windows 10. It shows the
      planted findings: Winlogon Taskman, the user Run entry in AppData, the forced browser extensions.
- [ ] With a locked BitLocker drive connected: Refresh lists it as "(locked or not ready)". The hint says how to
      unlock it. Picking it and pressing Start says "Pick a drive".
- [ ] Start PCPorter without administrator rights, choose "This PC" and press Start: "Administrator rights needed".
      Another PC's drive still works without administrator rights.

## 4. Images viewed (gallery)
- [ ] The OneDrive folder refusal works here too.
- [ ] Without administrator rights, "Also include the other accounts" is greyed out.
- [ ] Build the gallery into `C:\PCPorterCases\manual`. While it runs, the folder, checkboxes and Start are greyed
      out and Cancel works.
- [ ] Open the report:
  - [ ] Pictures load.
  - [ ] Filters and grouping change the grid: folder, website, status, month and source.
  - [ ] Arrow keys move between pictures. Enter opens the detail view, with zoom.
  - [ ] Exporting CSV works.
  - [ ] Print preview shows the contact sheet.
- [ ] Run it again with "Include web browser caches" unticked. There are no web pictures.

## 5. Narrator (Health page)
- [ ] Turn on Narrator (Ctrl+Win+Enter). Tab through the Health page: every control is read with a name, including
      the drive list ("Drive with the other PC's Windows").
- [ ] Start a scan. Narrator reads the steps ("Step 2 of 5: ...") and the finish message without moving focus.
- [ ] Cancel is read as "Stopping after the current step...", then "Scan stopped.".

## 6. Clean-up
- [ ] `subst P: /D`. Delete `C:\PCPorterCases\manual` if the results are no longer needed.

## Result
| Build (EXE SHA-256, first 12) | Date | Windows | Tester | Passed | Notes |
|---|---|---|---|---|---|
| | | | | | |
