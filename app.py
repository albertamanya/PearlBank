import os
import re
import json
import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

# --- Stronger secret-key handling ---
# Prefer environment variable. If missing, generate a strong random key for this process
# and warn. Never fall back to a hardcoded weak string.
_env_secret = os.environ.get("PEARLBANK_SECRET_KEY")
if _env_secret and len(_env_secret) >= 32:
    app.config["SECRET_KEY"] = _env_secret
else:
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    print(
        "[PearlBank] WARNING: PEARLBANK_SECRET_KEY not set or too short. "
        "Using a temporary random key for this run only. "
        "Set a long random value in the environment for persistent sessions."
    )

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "pearlbank.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set COOKIE_SECURE=1 only when deployed behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# --- Simple in-memory login lockout (resets on process restart; good enough for demo) ---
# Tracks failed attempts per email and temporary lockouts.
_failed_logins = defaultdict(list)  # email -> list of UTC datetimes
_LOCKOUT_THRESHOLD = 5
_LOCKOUT_MINUTES = 15
_ATTEMPT_WINDOW_MINUTES = 30


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def utc_now_dt():
    return datetime.now(timezone.utc).replace(microsecond=0)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.String(40), nullable=False, default=utc_now)
    transactions = db.relationship("Transaction", backref="user", lazy=True)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(24), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    balance_after_cents = db.Column(db.Integer, nullable=False)
    note_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.String(40), nullable=False, default=utc_now)
    record_hash = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)


def get_or_create_crypto_material():
    """Demo key files are local-development only. Protect/replace keys before real deployment."""
    key_path = os.path.join(BASE_DIR, "data_key.bin")
    sign_path = os.path.join(BASE_DIR, "signing_private.pem")
    pub_path = os.path.join(BASE_DIR, "signing_public.pem")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    if not os.path.exists(sign_path):
        private = Ed25519PrivateKey.generate()
        with open(sign_path, "wb") as f:
            f.write(
                private.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(pub_path, "wb") as f:
            f.write(
                private.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    with open(key_path, "rb") as f:
        aes_key = f.read()
    with open(sign_path, "rb") as f:
        signing_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_path, "rb") as f:
        public_key = f.read()
    return aes_key, signing_key, public_key


AES_KEY, SIGNING_KEY, PUBLIC_KEY_PEM = get_or_create_crypto_material()


def encrypt_note(note: str):
    if not note:
        return None
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, note.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_note(encrypted: str):
    """Return plaintext note or None if missing / cannot be decrypted."""
    if not encrypted:
        return None
    try:
        raw = base64.b64decode(encrypted)
        if len(raw) < 13:
            return None
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = AESGCM(AES_KEY).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


def transaction_payload(user_id, reference, kind, amount_cents, balance_after_cents, created_at):
    return json.dumps(
        {
            "user_id": user_id,
            "reference": reference,
            "kind": kind,
            "amount_cents": amount_cents,
            "balance_after_cents": balance_after_cents,
            "created_at": created_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_transaction(payload: bytes):
    digest = hashlib.sha256(payload).hexdigest()
    signature = base64.b64encode(SIGNING_KEY.sign(payload)).decode("ascii")
    return digest, signature, PUBLIC_KEY_PEM.decode("utf-8")


def verify_transaction(tx) -> bool:
    payload = transaction_payload(
        tx.user_id, tx.reference, tx.kind, tx.amount_cents, tx.balance_after_cents, tx.created_at
    )
    if hashlib.sha256(payload).hexdigest() != tx.record_hash:
        return False
    try:
        public_key = serialization.load_pem_public_key(tx.public_key.encode("utf-8"))
        public_key.verify(base64.b64decode(tx.signature), payload)
        return True
    except Exception:
        return False


def is_valid_email(email: str) -> bool:
    # Practical email pattern for a demo (not a full RFC validator).
    if not email or len(email) > 160:
        return False
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))


def is_strong_password(password: str) -> bool:
    """At least 6 characters, with mixed case and a digit or symbol."""
    if len(password) < 6:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit_or_symbol = any(not c.isalpha() for c in password)
    return has_upper and has_lower and has_digit_or_symbol


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to access your banking account.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    if not session.get("user_id"):
        return None
    return db.session.get(User, session["user_id"])


def _clean_old_attempts(email: str):
    cutoff = utc_now_dt() - timedelta(minutes=_ATTEMPT_WINDOW_MINUTES)
    _failed_logins[email] = [t for t in _failed_logins[email] if t > cutoff]


def is_locked_out(email: str) -> bool:
    _clean_old_attempts(email)
    recent = _failed_logins[email]
    if len(recent) < _LOCKOUT_THRESHOLD:
        return False
    # Locked if the N-th most recent attempt is still within the lockout window
    oldest_of_recent = sorted(recent)[-_LOCKOUT_THRESHOLD]
    return (utc_now_dt() - oldest_of_recent) < timedelta(minutes=_LOCKOUT_MINUTES)


def record_failed_login(email: str):
    _clean_old_attempts(email)
    _failed_logins[email].append(utc_now_dt())


def clear_failed_logins(email: str):
    _failed_logins.pop(email, None)


@app.template_filter("ugx")
def ugx(cents):
    return f"UGX {cents / 100:,.0f}"


@app.template_filter("decrypt_note")
def decrypt_note_filter(encrypted):
    return decrypt_note(encrypted) or ""


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(name) < 2:
            flash("Enter your full name (at least 2 characters).", "danger")
        elif not is_valid_email(email):
            flash("Enter a valid email address.", "danger")
        elif not is_strong_password(password):
            flash(
                "Password must be at least 10 characters and include uppercase, "
                "lowercase, and a number or symbol.",
                "danger",
            )
        elif password != confirm:
            flash("The passwords do not match.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists. Please sign in.", "warning")
        else:
            account_no = "PB" + "".join(secrets.choice("0123456789") for _ in range(10))
            while User.query.filter_by(account_number=account_no).first():
                account_no = "PB" + "".join(secrets.choice("0123456789") for _ in range(10))
            user = User(
                full_name=name,
                email=email,
                password_hash=generate_password_hash(password),
                account_number=account_no,
            )
            db.session.add(user)
            db.session.commit()
            session.clear()
            session["user_id"] = user.id
            flash("Welcome to PearlBank. Your demo account is ready.", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if is_locked_out(email):
            flash(
                f"Too many failed sign-in attempts. Please try again in {_LOCKOUT_MINUTES} minutes.",
                "danger",
            )
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            clear_failed_logins(email)
            session.clear()
            session["user_id"] = user.id
            flash("You have signed in successfully.", "success")
            return redirect(url_for("dashboard"))

        if email:
            record_failed_login(email)
        flash("We couldn't sign you in with those details. Check them and try again.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have signed out securely.", "success")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    transactions = (
        Transaction.query.filter_by(user_id=user.id).order_by(Transaction.id.desc()).limit(6).all()
    )
    balance = transactions[0].balance_after_cents if transactions else 0
    return render_template(
        "dashboard.html", user=user, balance=balance, transactions=transactions
    )


def post_money_movement(kind: str):
    """Create a single deposit or withdrawal under a short-lived exclusive lock on the user's rows."""
    user = current_user()
    amount_text = request.form.get("amount", "").strip()
    note = request.form.get("note", "").strip()[:180]

    try:
        amount = float(amount_text)
        cents = round(amount * 100)
        if cents <= 0 or cents > 100_000_000:
            raise ValueError()
    except (ValueError, TypeError):
        flash("Enter a valid amount greater than zero (maximum UGX 1,000,000).", "danger")
        return None

    # Serialize balance reads/writes for this user (SQLite supports BEGIN IMMEDIATE).
    try:
        db.session.execute(db.text("BEGIN IMMEDIATE"))
        latest = (
            Transaction.query.filter_by(user_id=user.id)
            .order_by(Transaction.id.desc())
            .with_for_update()
            .first()
        )
        balance = latest.balance_after_cents if latest else 0

        if kind == "withdrawal" and cents > balance:
            db.session.rollback()
            flash("Insufficient available balance. Please enter a smaller amount.", "danger")
            return None

        new_balance = balance + cents if kind == "deposit" else balance - cents
        created = utc_now()
        reference = "PB-" + secrets.token_hex(6).upper()
        payload = transaction_payload(user.id, reference, kind, cents, new_balance, created)
        digest, signature, pub = sign_transaction(payload)

        tx = Transaction(
            reference=reference,
            user_id=user.id,
            kind=kind,
            amount_cents=cents,
            balance_after_cents=new_balance,
            note_encrypted=encrypt_note(note),
            created_at=created,
            record_hash=digest,
            signature=signature,
            public_key=pub,
        )
        db.session.add(tx)
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("Could not complete the operation. Please try again.", "danger")
        return None

    flash(
        ("Deposit completed successfully." if kind == "deposit" else "Withdrawal completed successfully.")
        + f" Your reference is {reference}.",
        "success",
    )
    return tx


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        tx = post_money_movement("deposit")
        if tx:
            return redirect(url_for("receipt", reference=tx.reference))
    return render_template(
        "money_movement.html",
        action="Deposit Funds",
        kind="deposit",
        description="Add funds to your PearlBank demo account.",
    )


@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    if request.method == "POST":
        tx = post_money_movement("withdrawal")
        if tx:
            return redirect(url_for("receipt", reference=tx.reference))
    return render_template(
        "money_movement.html",
        action="Withdraw Funds",
        kind="withdrawal",
        description="Withdraw available funds from your demo account.",
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    user = current_user()
    if request.method == "POST":
        target_no = request.form.get("account_number", "").strip().upper()
        amount_text = request.form.get("amount", "").strip()
        note = request.form.get("note", "").strip()[:180]
        recipient = User.query.filter_by(account_number=target_no).first()

        try:
            cents = round(float(amount_text) * 100)
            if cents <= 0 or cents > 100_000_000:
                raise ValueError()
        except (ValueError, TypeError):
            cents = 0

        if not recipient or recipient.id == user.id:
            flash("Enter a valid recipient account number.", "danger")
        elif cents <= 0:
            flash("Enter a valid transfer amount.", "danger")
        else:
            try:
                # Exclusive lock for the whole transfer so both balances stay consistent.
                db.session.execute(db.text("BEGIN IMMEDIATE"))

                latest = (
                    Transaction.query.filter_by(user_id=user.id)
                    .order_by(Transaction.id.desc())
                    .with_for_update()
                    .first()
                )
                balance = latest.balance_after_cents if latest else 0

                if cents > balance:
                    db.session.rollback()
                    flash("Insufficient available balance for this transfer.", "danger")
                else:
                    created = utc_now()
                    ref = "PB-" + secrets.token_hex(6).upper()
                    sender_balance = balance - cents
                    sender_payload = transaction_payload(
                        user.id, ref, "transfer_out", cents, sender_balance, created
                    )
                    d1, s1, p1 = sign_transaction(sender_payload)

                    recipient_latest = (
                        Transaction.query.filter_by(user_id=recipient.id)
                        .order_by(Transaction.id.desc())
                        .with_for_update()
                        .first()
                    )
                    recipient_balance = (
                        recipient_latest.balance_after_cents if recipient_latest else 0
                    )
                    recipient_new_balance = recipient_balance + cents
                    recipient_payload = transaction_payload(
                        recipient.id,
                        ref + "-IN",
                        "transfer_in",
                        cents,
                        recipient_new_balance,
                        created,
                    )
                    d2, s2, p2 = sign_transaction(recipient_payload)

                    db.session.add_all(
                        [
                            Transaction(
                                reference=ref,
                                user_id=user.id,
                                kind="transfer_out",
                                amount_cents=cents,
                                balance_after_cents=sender_balance,
                                note_encrypted=encrypt_note(note),
                                created_at=created,
                                record_hash=d1,
                                signature=s1,
                                public_key=p1,
                            ),
                            Transaction(
                                reference=ref + "-IN",
                                user_id=recipient.id,
                                kind="transfer_in",
                                amount_cents=cents,
                                balance_after_cents=recipient_new_balance,
                                note_encrypted=encrypt_note(note),
                                created_at=created,
                                record_hash=d2,
                                signature=s2,
                                public_key=p2,
                            ),
                        ]
                    )
                    db.session.commit()
                    flash(f"Transfer completed successfully. Reference: {ref}.", "success")
                    return redirect(url_for("receipt", reference=ref))
            except Exception:
                db.session.rollback()
                flash("Could not complete the transfer. Please try again.", "danger")

    return render_template("transfer.html")


@app.route("/history")
@login_required
def history():
    user = current_user()
    transactions = (
        Transaction.query.filter_by(user_id=user.id).order_by(Transaction.id.desc()).all()
    )
    return render_template("history.html", transactions=transactions)


@app.route("/receipt/<reference>")
@login_required
def receipt(reference):
    user = current_user()
    tx = Transaction.query.filter_by(reference=reference, user_id=user.id).first()
    if not tx and reference.endswith("-IN"):
        tx = Transaction.query.filter_by(reference=reference[:-3], user_id=user.id).first()
    if not tx:
        tx = Transaction.query.filter_by(reference=reference, user_id=user.id).first()
    if not tx:
        abort(404)
    note = decrypt_note(tx.note_encrypted)
    return render_template("receipt.html", tx=tx, verified=verify_transaction(tx), note=note)


@app.route("/verify/<reference>")
@login_required
def verify_receipt(reference):
    user = current_user()
    tx = Transaction.query.filter_by(reference=reference, user_id=user.id).first()
    if not tx:
        tx = Transaction.query.filter_by(reference=reference + "-IN", user_id=user.id).first()
    if not tx:
        abort(404)
    note = decrypt_note(tx.note_encrypted)
    return render_template(
        "verify.html", tx=tx, verified=verify_transaction(tx), note=note
    )


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user())


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
