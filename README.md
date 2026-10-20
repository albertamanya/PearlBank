# PearlBank Secure

A Flask-based banking simulation for the BCS 2104 – Data Coding and Encryption assignment.

## Features
- User registration and secure login
- Deposits, withdrawals, and transfers
- AES-256-GCM encrypted transaction notes (Confidentiality)
- SHA-256 hashing of transaction records (Integrity)
- Password hashing + session management (Authentication)
- Ed25519 digital signatures (Non-repudiation)
- Receipt verification page

## How to Run (Mac / Linux)

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py

Then open: http://127.0.0.1:5000

## Important
This is a learning prototype with simulated funds only.
Do not use real money or real personal data.
