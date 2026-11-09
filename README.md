# ScopePilot
### Less noise. Better research.

ScopePilot is a local-first bug-bounty research workspace for **Android and iOS**. Track program scope, inspect response headers you collected with permission, and prepare evidence-led report drafts without invented vulnerability claims.

**Status: development preview, version 0.1.0.** This is not an autonomous bug-bounty solver. No confirmed vulnerabilities, live target scans, bounty rewards, or store approval are claimed.

## What works
- Responsive dark workspace with mint highlights, Overview, Programs, Research, and Reports.
- Official public directory links for discovery; manual program entry and JSON import.
- Exact-host and wildcard scope validation, excluded hosts, authorization confirmation, and expiry gates.
- Offline response-header inspection for missing CSP, HSTS, and MIME protection observations. All results are informational and need human validation.
- Cookie and authorization-header redaction; local report history and native share sheets.
- Separate Android application and iOS application, using bundled first-party interface assets. No hosted website is required.

## What is not implemented
There is no autonomous target probing, exploit generation or execution, AI provider integration, background internet agent, authenticated bounty-platform feed, automatic submission, billing, cloud sync, or cross-device migration. Opening a directory delegates browsing to the user's browser; it does not import that directory automatically. Mobile operating systems do not grant unrestricted background execution.

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
The debug APK is for development installation, not Play publication. ADB installation requires the user's tablet to be attached and authorized. The app has no Internet permission. It loads only bundled files through an isolated HTTPS origin and opens official directory/policy links in the system browser. The system share sheet is opened only on Export.

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
- `tests/ui.mjs`: Playwright create/analyze/report/persistence/rejection/navigation/mobile-layout flow. Install Playwright 1.51.1 and its Chromium first. Run a server on port 8137, then `node tests/ui.mjs`.
- GitHub Actions: unit/UI checks, Android assemble + lint, iOS device compilation, build artifacts.
- Native device smoke checks, signing, release channels, and store review remain separate release gates.

## Privacy and security
See [Privacy](docs/PRIVACY.md), [Security](SECURITY.md), and [Release checklist](docs/RELEASE.md). Data stays in this app's local WebView storage until the user exports it. Local storage is not an encrypted evidence vault. Do not paste credentials, personal data, or confidential production response bodies. The redactor handles known sensitive header names; it cannot detect every secret in notes or custom headers.

## Structure
- `web/`: first-party UI and pure evidence-analysis core
- `android/`: Java Android host and Gradle application
- `ios/`: SwiftUI/WKWebView host and XcodeGen project
- `scripts/sync_assets.py`: reproducible native asset bundling
- `tests/`: core and browser workflow checks
- `docs/STORE_LISTING.md`: honest app descriptions and launch positioning

No external security testing is performed by the build or tests. Test fixtures use reserved example domains without contacting them.
