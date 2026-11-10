# Saved report-note editing: validation status

This is a local source candidate based on canonical ScopePilot commit `30a3c3a065fe5728e3196c69fdd2a3cd826368e8`, not a new release.

## Implemented

Reports now supports editing researcher notes for manual and HAR-imported drafts. Notes can include owned-account reproduction steps, demonstrated impact and remediation. Known credential headers are redacted before persistence. Original evidence, program snapshot, capture timestamp, findings and unverified draft status remain unchanged.

Both input and redacted notes are limited to 32,000 characters. The complete UTF-8 report remains subject to the 180,000-byte export cap. Save is transactional: a failed storage write leaves the previous report intact and retains the editable text for retrying or copying. Cancel discards only the edit; navigation keeps unsaved notes in session memory. Reload/closing does not save unsaved text.

## Verified locally

- Canonical repository snapshot: all 45 source files matched GitHub blob hashes before modification.
- `npm test`: 42 tests pass, including eight new report-note regression tests.
- The new helper and storage-failure tests were observed failing before implementation and then passing.
- Independent source review found a redaction-expansion limit bug. A regression reproduced it before the fix, and the full 42-test suite passed afterward.
- JavaScript syntax checks for the application, generated bundle and browser tests pass.
- Asset synchronization is stable on a repeated run. The three generated web bundles are byte-identical.
- Whitespace checks pass.

## Not verified

The new real-browser regression covers HAR-note editing, redaction, evidence preservation, cancel, repeated opens, navigation recovery, local persistence, export, HTML-shaped text, failed storage writes and retry, historical reports, limits, deletion, mobile layout and no target traffic. It is included in `tests/ui.mjs` so existing browser jobs run it.

Browser execution in this workspace stopped before reaching app assertions because Chromium could not create a required local socket. The managed browser could not reach the sandbox's localhost server. Browser tests are authored, not passed. Run `node tests/ui.mjs` using the README's local server and Playwright setup on a supported executor before accepting this candidate.

No native build, simulator, physical-device, signing, release or store check was run for this source change. Existing release gates remain required. Android-specific development and delivery are on hold; the standard shared asset synchronizer refreshed its generated copy only. iPhone and shared-code validation are the next focus.

No live target requests, probing, exploit execution, report submission, remote publication or reward claims were made.
