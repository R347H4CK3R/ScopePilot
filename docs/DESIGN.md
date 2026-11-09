# ScopePilot implementation design
User intent: separate Android/iOS bug-bounty research app with understandable documentation and a strong commercial-style UI. User delegated design judgment. Builder choice: a shared offline web interface in narrow native hosts, avoiding remote code or target access from the mobile app.

Native-only separate interfaces would duplicate the research logic; a hosted website would require an account/server and reduce offline privacy. Bundled assets provide one testable logic core and two independently buildable app targets. Color system: deep forest background, warm mint actions, restrained typography, quiet cards, mobile bottom navigation and desktop sidebar.

Phase 0.1 implements genuine offline research organization and supplied-header observations. It does not pretend to solve arbitrary bounty programs autonomously. Any future active worker requires separately approved scope, methods, program rules, authorization expiry, execution isolation, and auditability. No third-party security targets are contacted during implementation or testing.

Plan: test scope and evidence contracts first; implement core; add accessible responsive views and persistence; add locked-down native shells and share/export; run core/UI checks; add mobile CI and honest release gates; publish to main after verification. Device distribution requires signed compatible artifacts and separate evidence.
