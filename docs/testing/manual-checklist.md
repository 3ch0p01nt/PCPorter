# PCPorter manual GUI checklist (tier 6)

Plan: [docs/plans/2026-11-26-regression-testing.md](../plans/2026-11-26-regression-testing.md). Run this before
handing a new build to another PC, after `scripts/regress.ps1 -Level release` has passed. It covers what the
automated tiers can't: the windows themselves. About 30 minutes. Automating it with FlaUI is planned for Phase 7.

Use the packaged EXE (`C:\PCPorter-dist\PCPorter\PCPorter.exe`), not a debug build. Write results to
`C:\PCPorterCases\manual\` (never OneDrive). Copy the table at the end into the release notes or `tasks/todo.md`.

## Setup
- [ ] Fake old-PC drive: `.\scripts\regress.ps1 -Level release` leaves the fixture at
      `C:\PCPorterCases\regress\fixture-oldpc`. Give it a drive letter so the app lists it as another PC's drive:
      `subst P: C:\PCPorterCases\regress\fixture-oldpc`. Remove it afterwards with `subst P: /D`.
- [ ] Optional: a BitLocker-locked drive (a USB stick, or a VHD with BitLocker turned on and then locked).

## 1. Start-up and Home
PCPorter always asks for administrator rights (`requireAdministrator`), so there is no non-administrator run to test.
- [ ] Double-click PCPorter.exe: the administrator prompt appears ("Unknown publisher" for an unsigned build). Press
      Yes. The title says `PCPorter  -  running as administrator`. Home shows three tiles.
- [ ] Start it again while it is open: a box says "PCPorter is already running." The first window stays open.
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
- [ ] Set it to `C:\PCPorterCases\regress\fixture-oldpc\out` (the same drive reached without the `P:` letter) and
      press Start: refused the same way. No `out` folder appears in the fixture.
- [ ] Save to `C:\PCPorterCases\manual` instead and run it. The report names OLDPC and Windows 10. It shows the
      planted findings: Winlogon Taskman, the user Run entry in AppData, the forced browser extensions.
- [ ] With a locked BitLocker drive connected: Refresh lists it as "(locked or not ready)". The hint says how to
      unlock it. Picking it and pressing Start says "Pick a drive".

## 4. Images viewed (gallery)
- [ ] The OneDrive folder refusal works here too.
- [ ] Build the gallery into `C:\PCPorterCases\manual`. While it runs, the folder, checkboxes and Start are greyed
      out and Cancel works.
- [ ] Note the folders in `C:\PCPorterCases\manual\PCPorter`. Start the gallery again and press Cancel while it
      runs: "Stopped", and no new case folder is left in `C:\PCPorterCases\manual\PCPorter` (not even a half-written
      one or a `work` folder).
- [ ] Open the report:
  - [ ] Pictures load.
  - [ ] Filters and grouping change the grid: folder, website, status, month and source.
  - [ ] Arrow keys move between pictures. Enter opens the detail view, with zoom.
  - [ ] Exporting CSV works.
  - [ ] Print preview shows the contact sheet.
- [ ] Run it again with "Include web browser caches" unticked. There are no web pictures.

## 5. Web history
- [ ] Home > "Explore my PC's history" opens Web history (also in the menu on the left). The "Go to Images viewed"
      link opens the gallery page.
- [ ] The OneDrive folder refusal works here too.
- [ ] "Also include the other accounts" and "Look for older history in existing restore points" can both be ticked.
- [ ] Build the report for this PC into `C:\PCPorterCases\manual`. While it runs, the inputs and Start are greyed out,
      the status line names each browser, and Cancel works ("Stopped", controls enabled again).
- [ ] When it ends: a sentence with the counts, "Open the report" and "Open the case folder" (History.html, case.db;
      no `work` folder left; Properties > Security lists only SYSTEM, Administrators and you).
- [ ] Open the report: the visit table scrolls, sorts and filters; Export CSV works; the charts and the coverage table
      match your browsers. No saved passwords, cookies or card numbers appear anywhere.
- [ ] The processing notes say whether restore points and Internet Explorer history were read.
- [ ] Another PC's drive: choose `P:\`. "All accounts" is ticked and greyed, restore points unticked and greyed.
      Saving to `P:\out` is refused. Saved to `C:\PCPorterCases\manual`, the report shows bob's Chrome (with 8
      recovered visits), Firefox and Internet Explorer history.

## 5b. Work is kept (navigation and restart)
- [ ] Start a Web history report (or a gallery), click Home in the menu while it runs, then click Web history again:
      the run is still going (status line, Cancel enabled), the folder and options you chose are unchanged, and it
      finishes on that page with "Open the report". Repeat once and press Cancel after coming back: it stops.
- [ ] Do the same from the Home tile ("Explore my PC's history"): it opens the same page, not a fresh one.
- [ ] Close PCPorter and start it again. Web history, Images viewed and Health show the folder, options and drive
      (only if still connected) from the last start, and "Last report: <date time> - <counts>" with Open the report /
      Open the case folder. Delete or move that report, restart: the "Last ..." line is gone.
- [ ] After a restart, press "Open the report" and "Open the case folder" on the remembered "Last report" line (on
      Health, Web history and Images viewed): each opens that run's report in the browser and its case folder.

## 5c. Closing during a job
- [ ] Start a health check (and, separately, a Web history report and a gallery) and close the window while it runs:
      PCPorter asks before closing. Answer No: the run goes on and finishes normally.
- [ ] Do it again and answer Yes: the window closes. Nothing is left behind: no half-written case folder and no
      `work` folder in the save folder, no PCPorter.exe in Task Manager, and `vssadmin list shadows` (administrator) lists
      no shadow copy made by PCPorter.

## 6. Narrator (Health and Web history pages)
- [ ] Turn on Narrator (Ctrl+Win+Enter). Tab through the Health page: every control is read with a name, including
      the drive list ("Drive with the other PC's Windows").
- [ ] Start a scan. Narrator reads the steps ("Step 2 of 5: ...") and the finish message without moving focus.
- [ ] Cancel is read as "Stopping after the current step...", then "Scan stopped.".
- [ ] Web history: every control is read with a name. During a run Narrator reads each browser as it is read, then
      "Report ready." with the counts.

## 7. Clean-up
- [ ] `subst P: /D`. Delete `C:\PCPorterCases\manual` if the results are no longer needed.

## Result
| Build (EXE SHA-256, first 12) | Date | Windows | Tester | Passed | Notes |
|---|---|---|---|---|---|
| | | | | | |
