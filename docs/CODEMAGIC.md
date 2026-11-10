# Manual Codemagic verification

Run workflow `scopepilot-verified-mobile` on the exact reviewed branch/commit. It uses the free-eligible M2 machine with Xcode 26.2, Node 22 and Java 17, capped at 60 minutes. There are no automatic triggers, signing secrets, public releases, or store publishing steps. Keep billing disabled and confirm enough included minutes before starting. Run one app at a time; three 60-minute attempts can use at most 180 build minutes before preparation/accounting overhead.

The workflow retains the current Node, asset-sync, browser, Android compile/lint, iOS simulator tests and unsigned device-build gates. A failed gate stops the pipeline. Diagnostics are private Codemagic artifacts; unsigned IPA and debug APK are promoted to `cm-output/verified/` only after the package's identity, version, arm64 device platform, source bytes and ZIP integrity pass. SHA-256 sums and the exact source commit are included.

This does not satisfy physical-device installation, signing, update-continuity or store gates. Native app version/build values are deliberately unchanged by this CI migration. Before distributing a new update, select appropriate update metadata and reverify that exact source. Do not merge or describe the new workflow as passed until a real hosted run succeeds. Never publish diagnostic output or private source by moving it to a public repository.

The Android SDK package installation uses already-accepted machine licenses and fails if additional acceptance is required. Gradle 8.9 is fetched from its official distribution and checked against the published SHA-256. No automatic license acceptance is added.

Local helper regression command: `python3 tests/test_codemagic_ipa.py`. Local Linux checks cannot substitute for the hosted Mac/SDK/browser stages.
