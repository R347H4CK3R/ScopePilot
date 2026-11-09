# Security and authorized use
ScopePilot 0.2 performs local evidence analysis and optional public-directory downloads. It has no scanner, shell bridge, exploit executor, remote scripts, or background testing jobs. Android permits GET requests only to the two hardcoded raw.githubusercontent.com snapshot URLs and blocks other WebView network requests. Browser CSP uses the same two allowed destinations; discovery requests omit credentials, reject redirects, time out after 45 seconds, and stop at 25 MB. Directory content is treated as untrusted data, never executable instructions or authorization. Both hosts only render bundled first-party HTML/JS; external links open in the browser.

Program authorization in this app is a researcher's record, not a legal permission grant or a substitute for reading the program policy. A host allowlist does not capture path restrictions, account rules, rate limits, geographic eligibility, or disallowed techniques. Do not treat the app's scope indicator as permission beyond the official terms. Wildcards do not match the apex, and exclusions take precedence.

Never submit a report solely because a response header is absent. Validate applicability, reproducibility, and actual impact; remove third-party data and use the program's approved disclosure process. Nothing in the app sends reports automatically.

Please report implementation security problems privately to the repository owner through an established private channel. Do not place sensitive target evidence in public issues. A dedicated security reporting address has not been configured yet.
