# Security Notes

## Design Goals

- keep wallet usage simple
- keep review scope public but controlled
- avoid publishing sensitive operational details

## Publicly Highlighted Protections

- self-custody wallet model
- PIN protection
- temporary lockout on repeated PIN failures
- session timeout behavior
- trusted origin checks
- request approval controls

## Public Review Scope

Only selected reviewable files are published in this public package.

Included public review files:

- `review/vault.js`
- `review/pin-security.js`
- `review/security-ticket.js`
- `review/crypto.js`
- `review/config.js`
- `review/storage.js`
- `review/SECURITY-REVIEW-NOTE.md`

## Distribution

Official browser distribution is through the Chrome Web Store listing linked on the public page.
