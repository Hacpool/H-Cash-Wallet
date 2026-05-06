# Security Review Note

This review package intentionally exposes only selected files that are sufficient to inspect:

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

- The wallet does not publish backend operational secrets in this review scope.
- Reviewers should treat `chrome.storage.session` as session-scoped extension storage, not as page-accessible local storage.
- The remaining notable design tradeoff is that an unlocked wallet session must temporarily hold signing capability inside the extension session context until the session expires or the wallet is locked.
