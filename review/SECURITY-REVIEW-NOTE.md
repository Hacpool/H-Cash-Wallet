# Security Review Note

This public review package intentionally exposes only selected files that are sufficient to inspect:

- wallet unlock and session handling
- PIN validation and temporary lockout flow
- request ticket verification
- encryption settings and key-derivation parameters
- origin allowlist rules
- session-vs-local storage boundaries

Included files:

- `vault.js`
- `pin-security.js`
- `security-ticket.js`
- `crypto.js`
- `config.js`
- `storage.js`

Important context:

- This review package is intentionally limited and does not expose the full wallet source tree.
- This review package does not include sensitive operational backend details.
- Reviewers should treat `chrome.storage.session` as session-scoped extension storage, not as page-accessible local storage.
- An unlocked wallet session temporarily holds signing capability inside the extension session context until the session expires or the wallet is locked.
