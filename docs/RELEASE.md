# Release readiness

Development preview, not a store-ready autonomous bounty product.

## Required before distribution
- [ ] All CI jobs green on the exact release commit; inspect APK/IPA metadata and artifact integrity.
- [ ] Android tablet install, launch, input, background/resume, import picker, export sheet and rotation tests.
- [ ] iPhone and iPad signed install, launch, storage persistence, import, export and safe-area tests.
- [ ] TalkBack/VoiceOver and larger-text checks on real devices.
- [ ] Release signing/keystore ownership and secure update continuity.
- [ ] Publisher identity, support contact, hosted privacy policy, store disclosures, screenshots and review.
- [ ] Document store review risks for embedded-web research utilities; no approval assumed.
- [ ] Only add verified, channel-compatible iPhone builds to Strata. Keep Android artifacts separate.

## Current limitations
Local SDK/GUI execution may be restricted in the build workspace. Use CI logs as evidence of compilation, not proof of installation or usability. Unsigned iOS archives need a compatible signing process. Debug APKs need a trusted distribution route; debug signing keys are not a stable public release identity.

## Future product work
Authenticated platform integrations; read-only policy-change tracking; research queue with provenance; explicit permitted-method configuration; approved, scoped remote worker for non-destructive checks; vetted evidence storage; human review and submission handoff. These are not shipped features. Public community snapshots and richer offline evidence analysis are implemented in 0.2, but their native networking and file-picker behavior still need device testing.
