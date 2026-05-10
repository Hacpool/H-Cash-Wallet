# H-Cash Wallet 0.3.3

## Highlights

- stabilized H-Cash connect approval flow on `hacpool.xyz`
- restored H-Cash native bid and auto-bid approval windows
- improved approval popup layout and close behavior
- improved wallet switcher layout and address visibility
- kept MoneyNex in connection-only mode

## Reliability updates

- connect approval no longer depends on fragile background-only timing
- native bid security ticket origin handling was aligned with the live site origin
- H-Cash bid compose and sign flows now open more reliably in standalone approval tabs
- canceling the H-Cash connect popup no longer leaves the site connected
- H-Cash connect state now clears correctly before each new approval attempt
- H-Cash auto-bid silent signing flow was stabilized for long-running bidding sessions
- auto-bid session unlock duration now extends dynamically up to 12 hours

## UI updates

- wallet switcher now shows full wallet addresses inside the popup width
- address book labels and actions are now in English
- request popup action buttons were resized to fit the approval window better
- activity entries now show pending and confirmed status indicators
- lock screen and private-key views received alignment and readability improvements
