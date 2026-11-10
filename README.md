# ScopePilot
### Less noise. Better research.

ScopePilot is a local-first bug-bounty research workspace for **Android and iOS**. Track program scope, inspect response headers you collected with permission, and prepare evidence-led report drafts without invented vulnerability claims.

**Status: development preview, version 0.2.0.** This is not an autonomous bug-bounty solver. No confirmed vulnerabilities, live target scans, bounty rewards, or store approval are claimed.

## What works
- Responsive dark workspace with mint highlights, Overview, Discover, Programs, Research, and Reports.
- Live, user-triggered discovery from two allowlisted public HackerOne/Bugcrowd community snapshots, with source and retrieval time. Search and paginate candidates, then review official policies before adding any scope.
- Manual program entry and JSON import. Discovery never grants permission; path-specific or unsupported restrictions force manual scope entry.
- Exact-host and wildcard scope validation, excluded hosts, authorization confirmation, and expiry gates.
- Offline response-header inspection for CSP, HSTS, MIME protection, cookie attributes, credentialed CORS context, and authenticated-response public caching. Optional supplied request headers enable contextual checks. All results include evidence, limitations, safe validation guidance, and references; nothing is labeled a confirmed vulnerability.
- Cookie and authorization-header redaction; local report history, editable research notes, and native share sheets. Add reproduction steps, demonstrated impact and remediation to existing drafts without changing captured evidence.
- Separate Android application and iOS application, using bundled first-party interface assets. No hosted website is required.

## What is not implemented
There is no autonomous target probing, exploit generation or execution, AI provider integration, background internet agent, authenticated bounty-platform feed, automatic submission, billing, cloud sync, or cross-device migration. Public listings are downloaded only when you press Refresh. Opening an official policy delegates browsing to the user's browser. Mobile operating systems do not grant unrestricted background execution.

A missing header is usually not a bounty-eligible vulnerability. ScopePilot does not infer exploitability from missing headers. It will never describe its own observations as confirmed bugs.

## Quick start
Requires Node 22+ and Python 3. No runtime web dependencies.

```sh
npm test
npm run sync
npm run serve
```
Open http://localhost:8080. Add a program, enter the official policy and permitted hosts, confirm permission, set a future expiry, and paste headers collected under that policy. Review the generated draft before exporting.

### Import format
Import a JSON array. Imported programs always require a fresh authorization confirmation. Example:

```json
[{"id":"your-program","name":"Your authorized program","policy":"https://example.com/security","hosts":["example.com","*.example.org"],"excluded":["admin.example.org"],"expires":"2099-01-01"}]
```
Example domains are documentation placeholders, not permission to test. Change the expiry to the actual approved research end date. Hosts use lowercase ASCII; URLs for evidence must use HTTPS on the default port, with no credentials, queries, or fragments. Non-HTTP program scopes and path-specific permissions require manual policy review; host matching cannot represent every program rule.

## Android
Requires JDK 17, Android SDK 35, and Gradle 8.9.

```sh
python3 scripts/sync_assets.py
gradle -p android assembleDebug lint
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```
The debug APK is for development installation, not Play publication. ADB installation requires the user's tablet to be attached and authorized. The app has Internet permission for two exact, allowlisted HTTPS public-directory JSON files. It renders only bundled code through an isolated HTTPS origin; research evidence is not sent to the directory. All other WebView network requests are blocked. Official policy links open in the system browser. The system share sheet is opened only on Export.

## iOS
Requires macOS, Xcode with iOS SDK, and XcodeGen.

```sh
python3 scripts/sync_assets.py
python3 scripts/make_icon.py
cd ios && xcodegen generate
open ScopePilot.xcodeproj
```
Select your development team and run on an authorized device. CI also builds an **unsigned** IPA for later signing. An unsigned IPA is not an App Store, TestFlight, or directly installable iPhone release. Do not add it as a verified catalog release until signing/install/launch checks pass in the intended channel.

## Verification
- `npm test`: deterministic scope, parsing, redaction, and import tests.
- `tests/ui.mjs`: Playwright create/analyze/report/persistence/rejection/navigation/mobile-layout flow, including saved-note editing, cancel, export, privacy and storage-failure recovery. Install Playwright 1.51.1 and its Chromium first. Run a server on port 8137, then `node tests/ui.mjs`.
- GitHub Actions: unit/UI checks, Android assemble + lint, iOS device compilation, build artifacts.
- Native device smoke checks, signing, release channels, and store review remain separate release gates.

## Privacy and security
See [Privacy](docs/PRIVACY.md), [Security](SECURITY.md), and [Release checklist](docs/RELEASE.md). Data stays in this app's local WebView storage until the user exports it. Local storage is not an encrypted evidence vault. Do not paste credentials, personal data, or confidential production response bodies. The redactor handles known sensitive header names; it cannot detect every secret in notes or custom headers.

## Structure
- `web/`: first-party UI, scope core, bounded public-directory ingestion, and offline evidence analysis
- `android/`: Java Android host and Gradle application
- `ios/`: SwiftUI/WKWebView host and XcodeGen project
- `scripts/sync_assets.py`: reproducible native asset bundling
- `tests/`: core and browser workflow checks
- `docs/STORE_LISTING.md`: honest app descriptions and launch positioning

Discovery is powered by an unofficial MIT-licensed community snapshot; see [third-party notices](docs/THIRD_PARTY_NOTICES.md). Retrieved scope may be stale or incomplete. Refresh downloads up to 25 MB without credentials and keeps candidate data in session memory. Review current official program terms, all exclusions, and eligibility yourself.

No external security testing is performed by the build or tests. Test fixtures use reserved example domains without contacting them.


## 0.3: Offline HAR evidence import

On Research, choose an authorized program and select a HAR capture from Files. ScopePilot reads up to 5 MB / 100 captured exchanges locally, never replays requests, and skips out-of-scope or query-bearing URLs. Preview the resulting evidence drafts, then explicitly save or discard them. Request/response bodies, custom headers and credential values are not retained. Review retained URLs and security-policy headers for sensitive data. Capture timestamps are user-supplied, not independently verified. This is evidence triage, not confirmed vulnerability discovery or an automated submission.
