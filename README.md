# PearlBank Secure — University Project Prototype (Improved)

A Flask-based **banking simulation** for Data Coding and Encryption assignment. It includes registration, login/logout, dashboard, deposits, withdrawals, transfers between demo accounts, transaction history, receipts, and receipt verification.

> **Important:** This is a learning prototype with simulated funds. It is not a real bank, payment service, or production financial system. Do not use real customer information or connect it to real money.

## What was strengthened in this version

| Gap in original | Improvement |
|-----------------|-------------|
| Notes encrypted but never decrypted/shown | Full AES-256-GCM decrypt path + notes displayed on receipts, verification page, and history |
| Weak default secret key | Requires `PEARLBANK_SECRET_KEY` (≥32 chars) or generates a strong temporary key and warns |
| Minimal password/email rules | Stronger password policy (mixed case + digit/symbol) and practical email regex |
| No login protection | Simple in-memory lockout after 5 failed attempts in a 30-minute window (15-minute lock) |
| Race-prone balance updates | `BEGIN IMMEDIATE` + `with_for_update()` around balance reads and writes for deposits, withdrawals, and transfers |
| Incomplete transfer references | Recipient entry now uses a distinct `…-IN` reference that is also signed correctly |
| Sparse documentation | Clearer security notes and limitations |

## Requirements
- Python 3.10 or newer
- Windows 10/11 (also works on macOS/Linux)

## Run on Windows
1. Extract the `PearlBank` folder somewhere easy to find, for example Desktop.
2. Open the folder in File Explorer.
3. Click the address bar, type `cmd`, and press Enter.
4. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install dependencies:
   ```bat
   python -m pip install -r requirements.txt
   ```
6. Set a development secret key for this terminal session (recommended):
   ```bat
   set PEARLBANK_SECRET_KEY=replace-this-with-a-long-random-secret-at-least-32-chars
   ```
7. Start the application:
   ```bat
   python app.py
   ```
8. Open `http://127.0.0.1:5000` in your browser and register a demo account.

To test transfers, register a second account in another browser/private window and use its account number shown on the Profile page. Deposit simulated funds before withdrawing or transferring.

## Open on a phone on the same Wi-Fi
Find the Windows computer's LAN IPv4 address using `ipconfig`. On your phone, open `http://COMPUTER-IP:5000` (replace with the computer's actual IPv4 address). Both devices must be on the same Wi-Fi, and Windows Firewall may ask permission. Do not expose this development server directly to the public internet.

## Security features in the prototype
- Passwords are stored using Werkzeug's password-hashing functions, never as plain text.
- Flask-WTF enables CSRF protection for forms.
- AES-256-GCM encrypts optional transaction notes; notes are decrypted only for the account owner when viewing history/receipts.
- SHA-256 hashes and Ed25519 signatures are created for transaction records and checked on the verification page.
- Session cookies are HttpOnly and SameSite=Lax.
- Users can only view their own transactions and receipts.
- Basic login lockout after repeated failures (demo-grade, in-memory).
- Stronger registration validation for email and password.
- Short exclusive database transactions around balance updates to reduce race conditions on SQLite.

## Key and database files
On first run, the app creates:
- `pearlbank.db` — local demo database
- `data_key.bin` — AES encryption key
- `signing_private.pem` — Ed25519 signing private key
- `signing_public.pem` — public key

These are generated for local demonstration. Keep them private and back them up safely if preserving demo records. Do not commit secrets or real data to GitHub. The signing key is a single application-level key in this prototype, not an individual customer's personal signing key; therefore the demo illustrates signed records but is not a complete legally qualified non-repudiation service.

## Before any real-world deployment
This prototype must not be treated as production banking software. A production system would need, at minimum:
- Full security review and penetration testing
- HTTPS and secure deployment configuration
- Robust key management (preferably a KMS/HSM)
- Per-user transaction authorization / signing
- Persistent rate limiting and account recovery controls
- Stronger session management and multi-factor authentication
- Proper double-entry ledger with database-level consistency guarantees
- Monitoring, backups, privacy controls, and legal/regulatory review

Do not handle real funds without the necessary authorization and professional review.
