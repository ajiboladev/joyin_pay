# JOYIN PAY

Black + #5253fb banking demo: HTML, CSS, vanilla JS, Firebase Auth + Firestore.

## Setup
1. Firebase Console: create project, enable Authentication > Email/Password, create a Firestore database.
2. Paste your web config into `js/firebase-config.js`.
3. Firestore > Rules: paste `firestore.rules` and publish.
4. Serve over http (ES modules do not work from file://): `npx serve .` or Firebase Hosting. Add your domain under Authentication > Settings > Authorized domains.

## Data model
- `accountNumbers/{no}` -> `{uid, name}` (lookup index, GET only)
- `users/{uid}` -> profile (owner only)
- `users/{uid}/private/wallet` -> `{balance (kobo, integer), pinHash, salt, lastTx}` (owner read only)
- `users/{uid}/history/{txId}` -> history rows (50 per page)
- `transfers/{txId}` -> immutable ledger

Money is stored in kobo (integers), so no floating point errors.

## Security notes (read this)
Rules force every transfer to debit the sender by the exact amount, credit only via a matching transfer, and never allow negative balances.
PIN checking happens in the browser because there is no server. The PIN hash is PBKDF2 (150k rounds) and is only readable by its owner, but a determined attacker holding a logged-in session could brute force it offline. Before real money, move transfers and PIN verification into a Cloud Function (Admin SDK) and lock the wallet rules to `allow write: if false`.
