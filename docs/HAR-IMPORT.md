# Captured evidence, without replaying traffic

ScopePilot 0.3 adds offline HAR analysis to the iPhone and Android workspace.

## Workflow

1. Read the current official program policy and record only authorized hosts, exclusions, and an authorization expiry in Programs.
2. In your own browser, collect a small capture using your own test accounts and only the program's permitted methods. ScopePilot does not collect or intercept traffic.
3. Export that capture as HAR. Prefer the browser's sanitized export option. Check the file for private data before importing it.
4. In Research, select the correct program and choose the HAR file from Files. Maximum: 5 MB and 100 exchanges. Nothing is uploaded or replayed.
5. Review the prepared drafts and skip counts. Expand each report to check its retained URL, response policies, observations, and context. Save reviewed drafts or discard the preview.
6. Add actual reproduction steps and impact through your reporting workflow. Export individual drafts from Reports, review for private data again, and submit yourself through the official program channel.

## What analysis can and cannot establish

The same deterministic header analyzer reviews transport, MIME, CSP, cookie attributes, supplied CORS context, and explicit public caching. These are configuration observations, not validated vulnerabilities. Missing headers or permissive policies frequently have no bounty-eligible impact. A HAR cannot prove source authenticity, capture time, cookie sensitivity, intended trust relationships, or exploitability.

The importer preserves response status and normalizes the HTTP-version line solely for parser compatibility. Only selected security-relevant headers are retained. It discards response/request bodies, custom headers, raw credentials and cookie values, and all query-bearing or unsupported URLs. Unknown headers are not treated as evidence. Repeated identical retained exchanges are collapsed within one import; different evidence is kept. Out-of-scope URLs are not shown in skip messages. Importing twice can produce duplicate drafts.

URL paths and policy-header values can still contain private information. Automatic filtering is not a universal secret detector. The original HAR remains in the user's Files storage and is not deleted or modified. Reports stay local until the user exports them; no submission is sent.

## Release verification

Unit coverage: scope/exclusions, authorization expiry, mixed-origin captures, bounds, malformed headers, privacy filtering, duplicate handling and changed evidence. Browser coverage: preview, discard, save and reload persistence, in addition to the existing manual-evidence workflow. Native file-picker behavior and physical-device compatibility must be checked separately; simulator launch/navigation does not establish them.
