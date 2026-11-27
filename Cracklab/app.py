"""
CrackLab — Educational Password Security & Hashing Demo
Runs strictly locally on 127.0.0.1. All password analysis and hashing
happens strictly in memory; nothing is ever logged or saved to disk.
"""

import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

import bcrypt
from argon2 import PasswordHasher
from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from zxcvbn import zxcvbn

# Base paths
BASE_DIR = Path(__file__).resolve().parent
WORDLIST_PATH = BASE_DIR / "data" / "wordlist.txt"

# Safety limits so the UI stays fast and never crashes on huge inputs
MAX_PASSWORD_LENGTH = 256
BCRYPT_ROUNDS = 10
BCRYPT_MAX_BYTES = 72
BCRYPT_BATTLE_MAX_SECONDS = 1.8
DEMO_PASSWORD = "password123"

app = Flask(__name__)

# Argon2id hasher with standard secure defaults
ARGON2_HASHER = PasswordHasher()

# Keyboard walk patterns for clear beginner-friendly weakness detection
KEYBOARD_PATTERNS = (
    "qwerty",
    "qwertz",
    "azerty",
    "asdf",
    "zxcv",
    "1234",
    "2345",
    "3456",
    "4567",
    "5678",
    "6789",
    "7890",
    "0987",
    "9876",
    "6543",
    "4321",
)


def load_wordlist_and_rainbow_table():
    """
    Load the bundled common-password wordlist into memory and build an
    unsalted MD5 rainbow lookup table once when the server starts.
    """
    words = []
    rainbow_table = {}

    if not WORDLIST_PATH.exists():
        return words, set(), rainbow_table

    with WORDLIST_PATH.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            words.append(candidate)
            md5_hex = hashlib.md5(candidate.encode("utf-8")).hexdigest()
            # Keep first occurrence so common passwords map predictably
            if md5_hex not in rainbow_table:
                rainbow_table[md5_hex] = candidate

    return words, set(words), rainbow_table


WORDLIST, WORDLIST_SET, RAINBOW_TABLE = load_wordlist_and_rainbow_table()


def parse_password_payload(data):
    """
    Validate incoming JSON payload and extract the password safely.
    Returns (password, error_message) without ever logging the password.
    """
    if not isinstance(data, dict):
        return None, "Invalid request format. Expected a JSON object."

    password = data.get("password", "")
    if not isinstance(password, str):
        return None, "Password must be text."

    if len(password) == 0:
        return None, "Please enter a password to analyze."

    if len(password) > MAX_PASSWORD_LENGTH:
        return (
            None,
            f"Password is too long for this live demo (maximum {MAX_PASSWORD_LENGTH} characters).",
        )

    return password, None


def prepare_bcrypt_bytes(password):
    """
    Convert password to UTF-8 bytes and respect bcrypt's 72-byte limit.
    Returns (password_bytes, was_truncated).
    """
    raw = password.encode("utf-8")
    if len(raw) > BCRYPT_MAX_BYTES:
        return raw[:BCRYPT_MAX_BYTES], True
    return raw, False


def format_duration_seconds(seconds):
    """
    Format a duration in seconds into a clear human-readable string
    without overflowing on astronomically large keyspaces.
    """
    if seconds <= 0:
        return "< 1 ms"
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f} µs"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} seconds"

    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"

    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"

    days = hours / 24
    if days < 365.25:
        return f"{days:.1f} days"

    years = days / 365.25
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.1f} billion years"
    return "Over 1 trillion years"


def estimate_keyspace(password):
    """
    Estimate the brute-force search space size based on which character sets
    appear in the password and its total length.
    """
    has_lower = any("a" <= ch <= "z" for ch in password)
    has_upper = any("A" <= ch <= "Z" for ch in password)
    has_digit = any("0" <= ch <= "9" for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    has_unicode = any(ord(ch) > 127 for ch in password)

    pool_size = 0
    pools = []
    if has_lower:
        pool_size += 26
        pools.append("lowercase (26)")
    if has_upper:
        pool_size += 26
        pools.append("uppercase (26)")
    if has_digit:
        pool_size += 10
        pools.append("digits (10)")
    if has_symbol:
        pool_size += 33
        pools.append("symbols (33)")
    if has_unicode:
        pool_size += 64
        pools.append("unicode (64)")

    if pool_size == 0:
        pool_size = 26
        pools.append("lowercase (26)")

    # Total combinations = pool_size ^ length
    total_combinations = pool_size ** len(password)
    return {
        "length": len(password),
        "pool_size": pool_size,
        "pools": pools,
        "total_combinations": total_combinations,
        "average_guesses": total_combinations / 2,
    }


def analyze_password_strength(password):
    """
    Evaluate password strength using zxcvbn plus explicit security checks
    for common words, keyboard patterns, repeated chars, length, and leaked styles.
    """
    # Slice to 100 chars for zxcvbn so long passphrases stay instant
    zxcvbn_result = zxcvbn(password[:100])
    score = int(zxcvbn_result["score"])  # 0 to 4
    lower_pw = password.lower()

    reasons = []
    tips = []

    # 1. Check length
    if len(password) < 8:
        reasons.append(
            f"Too short ({len(password)} characters): short passwords have a tiny keyspace and can be brute-forced quickly."
        )
        tips.append("Increase length to at least 12–16 characters (length beats complexity).")
    elif len(password) < 12:
        reasons.append(
            f"Moderate length ({len(password)} characters): under 12 characters is still risky against fast offline cracking."
        )
        tips.append("Aim for 14+ characters using 3–4 unrelated random words.")

    # 2. Check common / leaked wordlist match
    in_wordlist = password in WORDLIST_SET or lower_pw in WORDLIST_SET
    if in_wordlist:
        reasons.append(
            "Common / leaked-style password: this exact password appears in our 10,000-entry leaked password list."
        )
        tips.append("Avoid any well-known password; attackers always test leaked wordlists first.")

    # 3. Check zxcvbn dictionary or leaked-style pattern (word + trailing digits/symbols)
    sequence = zxcvbn_result.get("sequence", [])
    has_dict_match = any(match.get("pattern") == "dictionary" for match in sequence)
    leaked_style = bool(re.match(r"^[a-zA-Z]{3,}[0-9]{1,4}[!@#$%^&*]?$", password))

    if has_dict_match and not in_wordlist:
        reasons.append(
            "Contains a common dictionary word or name that cracking tools guess in seconds."
        )
        tips.append("Combine 4+ unexpected words instead of one familiar word.")

    if leaked_style and not in_wordlist:
        reasons.append(
            "Leaked-style pattern (word + numbers/symbol at the end): rules like 'Word123!' are standard in attacker rulebooks."
        )
        tips.append("Don't just tack numbers like '123' or '2024' onto the end of a word.")

    # 4. Check keyboard patterns
    has_spatial = any(match.get("pattern") == "spatial" for match in sequence)
    has_kbd_walk = any(pat in lower_pw for pat in KEYBOARD_PATTERNS)
    if has_spatial or has_kbd_walk:
        reasons.append(
            "Keyboard pattern detected (e.g., 'qwerty', 'asdf', or '1234'): attackers test keyboard walks early."
        )
        tips.append("Replace sequential keys or keyboard rows with non-sequential characters.")

    # 5. Check repeated characters
    has_repeat_match = any(match.get("pattern") == "repeat" for match in sequence)
    has_triple_repeat = bool(re.search(r"(.)\1{2,}", password))
    low_diversity = len(password) >= 4 and len(set(password)) <= max(2, len(password) // 3)
    if has_repeat_match or has_triple_repeat or low_diversity:
        reasons.append(
            "Repeated characters reduce true randomness and shrink the search space."
        )
        tips.append("Mix distinct characters or unrelated words rather than repeating letters or digits.")

    # If the password is strong and triggered no weakness flags, explain why it's strong
    if not reasons:
        if score >= 3:
            reasons.append(
                "No obvious dictionary words, keyboard walks, or repeated patterns were detected."
            )
        else:
            reasons.append(
                "Predictable structure detected by zxcvbn pattern matching."
            )

    # Pull any helpful zxcvbn suggestion if we still have fewer than 2 tips
    zxcvbn_feedback = zxcvbn_result.get("feedback", {})
    for suggestion in zxcvbn_feedback.get("suggestions", []):
        if len(tips) >= 3:
            break
        if suggestion not in tips:
            tips.append(suggestion)

    if len(tips) == 0:
        tips = [
            "Use a unique 4-word random passphrase (16+ characters) for every account.",
            "Store complex passwords in a password manager instead of reusing patterns.",
        ]
    elif len(tips) == 1:
        tips.append("Never reuse this password across multiple websites.")

    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    colors = ["#ff4d6d", "#ff7b54", "#ffb703", "#38bdf8", "#00f59b"]

    return {
        "score": score,
        "label": labels[score],
        "color": colors[score],
        "length": len(password),
        "guesses_log10": round(float(zxcvbn_result.get("guesses_log10", 0)), 2),
        "reasons": reasons[:5],
        "tips": tips[:3],
        "in_wordlist": in_wordlist,
    }


def compute_all_hashes(password):
    """
    Hash the password with MD5, SHA-1, SHA-256, bcrypt, and Argon2id,
    measuring the real compute time in milliseconds for each algorithm.
    """
    encoded = password.encode("utf-8")
    bcrypt_bytes, bcrypt_truncated = prepare_bcrypt_bytes(password)

    results = []

    # Fast legacy / general-purpose hashes
    fast_algos = [
        ("MD5", hashlib.md5, "Broken & Instant", "danger"),
        ("SHA-1", hashlib.sha1, "Broken & Too Fast", "danger"),
        ("SHA-256", hashlib.sha256, "Too Fast for Passwords", "warning"),
    ]

    for name, hash_fn, badge, level in fast_algos:
        start = time.perf_counter()
        digest = hash_fn(encoded).hexdigest()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        results.append(
            {
                "algorithm": name,
                "hash": digest,
                "time_ms": round(elapsed_ms, 4),
                "time_display": f"{elapsed_ms:.4f} ms"
                if elapsed_ms >= 0.01
                else f"{elapsed_ms * 1000:.2f} µs",
                "badge": badge,
                "level": level,
                "salted": False,
            }
        )

    # Slow adaptive password hashing: bcrypt
    start = time.perf_counter()
    bcrypt_digest = bcrypt.hashpw(
        bcrypt_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("utf-8")
    bcrypt_ms = (time.perf_counter() - start) * 1000.0
    results.append(
        {
            "algorithm": f"bcrypt (cost={BCRYPT_ROUNDS})",
            "hash": bcrypt_digest,
            "time_ms": round(bcrypt_ms, 2),
            "time_display": f"{bcrypt_ms:.2f} ms",
            "badge": "Strong (CPU-Hard)",
            "level": "safe",
            "salted": True,
            "note": "Truncated to 72 bytes (bcrypt limit)." if bcrypt_truncated else None,
        }
    )

    # Modern memory-hard password hashing: Argon2id
    start = time.perf_counter()
    argon2_digest = ARGON2_HASHER.hash(password)
    argon2_ms = (time.perf_counter() - start) * 1000.0
    results.append(
        {
            "algorithm": "Argon2id",
            "hash": argon2_digest,
            "time_ms": round(argon2_ms, 2),
            "time_display": f"{argon2_ms:.2f} ms",
            "badge": "Recommended (Memory-Hard)",
            "level": "safe",
            "salted": True,
        }
    )

    return results


def compute_salt_demo(password):
    """
    Hash the exact same password twice with unsalted algorithms (MD5, SHA-256)
    versus salted algorithms (bcrypt, Argon2id) to prove why salts prevent
    identical hashes.
    """
    encoded = password.encode("utf-8")
    bcrypt_bytes, _ = prepare_bcrypt_bytes(password)

    md5_first = hashlib.md5(encoded).hexdigest()
    md5_second = hashlib.md5(encoded).hexdigest()

    sha256_first = hashlib.sha256(encoded).hexdigest()
    sha256_second = hashlib.sha256(encoded).hexdigest()

    bcrypt_first = bcrypt.hashpw(
        bcrypt_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("utf-8")
    bcrypt_second = bcrypt.hashpw(
        bcrypt_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("utf-8")

    argon2_first = ARGON2_HASHER.hash(password)
    argon2_second = ARGON2_HASHER.hash(password)

    return {
        "explanation": (
            "A salt is a unique random string added to every password before hashing "
            "so identical passwords produce completely different hashes."
        ),
        "rows": [
            {
                "algorithm": "MD5 (Unsalted)",
                "hash_1": md5_first,
                "hash_2": md5_second,
                "identical": md5_first == md5_second,
            },
            {
                "algorithm": "SHA-256 (Unsalted)",
                "hash_1": sha256_first,
                "hash_2": sha256_second,
                "identical": sha256_first == sha256_second,
            },
            {
                "algorithm": f"bcrypt (Auto-Salted, cost={BCRYPT_ROUNDS})",
                "hash_1": bcrypt_first,
                "hash_2": bcrypt_second,
                "identical": bcrypt_first == bcrypt_second,
            },
            {
                "algorithm": "Argon2id (Auto-Salted)",
                "hash_1": argon2_first,
                "hash_2": argon2_second,
                "identical": argon2_first == argon2_second,
            },
        ],
    }


def run_machine_benchmark():
    """
    Measure this machine's real hashes/second rate for MD5, SHA-1, SHA-256,
    bcrypt, and Argon2id using short real loops (never faked numbers).
    """
    sample = b"cracklab-benchmark-sample"
    sample_str = "cracklab-benchmark-sample"
    fast_iterations = 40_000

    benchmarks = []

    for label, key, fn in (
        ("MD5", "md5", hashlib.md5),
        ("SHA-1", "sha1", hashlib.sha1),
        ("SHA-256", "sha256", hashlib.sha256),
    ):
        start = time.perf_counter()
        for _ in range(fast_iterations):
            fn(sample).digest()
        elapsed = max(time.perf_counter() - start, 1e-6)
        hps = fast_iterations / elapsed
        benchmarks.append(
            {
                "key": key,
                "algorithm": label,
                "hashes_per_sec": round(hps, 2),
                "ms_per_hash": round((elapsed / fast_iterations) * 1000.0, 6),
                "iterations_measured": fast_iterations,
                "measured_seconds": round(elapsed, 4),
            }
        )

    # Measure bcrypt with 3 real hashes so benchmark finishes in ~0.2s
    bcrypt_iters = 3
    start = time.perf_counter()
    for _ in range(bcrypt_iters):
        bcrypt.hashpw(sample, bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    bcrypt_elapsed = max(time.perf_counter() - start, 1e-6)
    benchmarks.append(
        {
            "key": "bcrypt",
            "algorithm": f"bcrypt (cost={BCRYPT_ROUNDS})",
            "hashes_per_sec": round(bcrypt_iters / bcrypt_elapsed, 2),
            "ms_per_hash": round((bcrypt_elapsed / bcrypt_iters) * 1000.0, 2),
            "iterations_measured": bcrypt_iters,
            "measured_seconds": round(bcrypt_elapsed, 4),
        }
    )

    # Measure Argon2id with 3 real hashes
    argon2_iters = 3
    start = time.perf_counter()
    for _ in range(argon2_iters):
        ARGON2_HASHER.hash(sample_str)
    argon2_elapsed = max(time.perf_counter() - start, 1e-6)
    benchmarks.append(
        {
            "key": "argon2",
            "algorithm": "Argon2id",
            "hashes_per_sec": round(argon2_iters / argon2_elapsed, 2),
            "ms_per_hash": round((argon2_elapsed / argon2_iters) * 1000.0, 2),
            "iterations_measured": argon2_iters,
            "measured_seconds": round(argon2_elapsed, 4),
        }
    )

    return benchmarks


def build_keyspace_estimates(password, benchmarks):
    """
    Combine the password's estimated keyspace with real measured CPU speeds
    to estimate brute-force crack time for each hashing algorithm.
    """
    keyspace = estimate_keyspace(password)
    avg_guesses = keyspace["average_guesses"]

    estimates = []
    for item in benchmarks:
        hps = max(item["hashes_per_sec"], 0.01)
        est_seconds = avg_guesses / hps
        estimates.append(
            {
                "algorithm": item["algorithm"],
                "measured_hps": item["hashes_per_sec"],
                "estimated_time": format_duration_seconds(est_seconds),
                "estimated_seconds": est_seconds,
            }
        )

    return {
        "keyspace": {
            "length": keyspace["length"],
            "pool_size": keyspace["pool_size"],
            "pools": keyspace["pools"],
            "total_combinations_sci": f"{keyspace['total_combinations']:.2e}",
            "average_guesses_sci": f"{avg_guesses:.2e}",
        },
        "estimates": estimates,
    }


def lookup_rainbow_table(password):
    """
    Look up the password's unsalted MD5 hash in the precomputed 10,000-word
    rainbow table, then add a random salt and show why the lookup fails.
    """
    start = time.perf_counter()
    unsalted_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
    recovered = RAINBOW_TABLE.get(unsalted_md5)
    unsalted_lookup_ms = (time.perf_counter() - start) * 1000.0

    # Add a random 8-byte hex salt and look up again
    salt = secrets.token_hex(8)
    salted_start = time.perf_counter()
    salted_md5 = hashlib.md5(f"{salt}{password}".encode("utf-8")).hexdigest()
    salted_recovered = RAINBOW_TABLE.get(salted_md5)
    salted_lookup_ms = (time.perf_counter() - salted_start) * 1000.0

    return {
        "table_size": len(RAINBOW_TABLE),
        "unsalted": {
            "hash": unsalted_md5,
            "found": recovered is not None,
            "recovered_password": recovered if recovered is not None else None,
            "lookup_ms": round(unsalted_lookup_ms, 5),
        },
        "salted": {
            "salt": salt,
            "hash": salted_md5,
            "found": salted_recovered is not None,
            "lookup_ms": round(salted_lookup_ms, 5),
        },
    }


@app.route("/")
def index():
    """Render the single-page CrackLab dashboard."""
    return render_template(
        "index.html",
        wordlist_size=len(WORDLIST),
        demo_password=DEMO_PASSWORD,
        bcrypt_rounds=BCRYPT_ROUNDS,
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Analyze password strength, compute all 5 hashes with real timings,
    and run the double-hash salt demonstration in one fast response.
    """
    data = request.get_json(silent=True)
    password, error = parse_password_payload(data)
    if error:
        return jsonify({"error": error}), 400

    return jsonify(
        {
            "strength": analyze_password_strength(password),
            "hashes": compute_all_hashes(password),
            "salt_demo": compute_salt_demo(password),
        }
    )


@app.route("/api/rainbow-table", methods=["POST"])
def api_rainbow_table():
    """Run the unsalted vs salted MD5 rainbow table lookup demo."""
    data = request.get_json(silent=True)
    password, error = parse_password_payload(data)
    if error:
        return jsonify({"error": error}), 400

    return jsonify(lookup_rainbow_table(password))


@app.route("/api/benchmark", methods=["GET", "POST"])
def api_benchmark():
    """
    Return real measured hashes/second on this machine for all 5 algorithms.
    If a password is provided via POST, also compute keyspace crack estimates.
    """
    benchmarks = run_machine_benchmark()
    response = {"benchmarks": benchmarks}

    if request.method == "POST":
        data = request.get_json(silent=True)
        password, error = parse_password_payload(data)
        if error:
            return jsonify({"error": error}), 400
        response["estimates"] = build_keyspace_estimates(password, benchmarks)

    return jsonify(response)


@app.route("/api/crack-battle", methods=["POST"])
def api_crack_battle():
    """
    Stream a live dictionary attack comparing MD5 against bcrypt using NDJSON
    events so the frontend can animate live attempts, elapsed time, and progress.
    """
    data = request.get_json(silent=True)
    password, error = parse_password_payload(data)
    if error:
        return jsonify({"error": error}), 400

    total_words = len(WORDLIST)
    target_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
    bcrypt_bytes, bcrypt_truncated = prepare_bcrypt_bytes(password)
    target_bcrypt = bcrypt.hashpw(
        bcrypt_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    )

    def generate_events():
        def emit(payload):
            return json.dumps(payload) + "\n"

        yield emit(
            {
                "type": "start",
                "wordlist_size": total_words,
                "target_md5": target_md5,
                "target_bcrypt": target_bcrypt.decode("utf-8"),
                "bcrypt_truncated": bcrypt_truncated,
                "bcrypt_window_seconds": BCRYPT_BATTLE_MAX_SECONDS,
            }
        )

        # --- Phase 1: Real MD5 dictionary attack across bundled wordlist ---
        md5_start = time.perf_counter()
        md5_found = False
        md5_attempts = 0
        chunk_size = 100

        for idx, candidate in enumerate(WORDLIST, start=1):
            md5_attempts = idx
            if hashlib.md5(candidate.encode("utf-8")).hexdigest() == target_md5:
                md5_found = True
                break
            if idx % chunk_size == 0:
                elapsed = max(time.perf_counter() - md5_start, 1e-6)
                yield emit(
                    {
                        "type": "md5_progress",
                        "attempts": md5_attempts,
                        "total": total_words,
                        "elapsed_ms": round(elapsed * 1000.0, 2),
                        "hps": round(md5_attempts / elapsed, 1),
                    }
                )

        md5_elapsed = max(time.perf_counter() - md5_start, 1e-6)
        yield emit(
            {
                "type": "md5_done",
                "found": md5_found,
                "attempts": md5_attempts,
                "total": total_words,
                "elapsed_ms": round(md5_elapsed * 1000.0, 3),
                "hps": round(md5_attempts / md5_elapsed, 1),
            }
        )

        # --- Phase 2: Real bcrypt dictionary attack capped to a short time window ---
        bcrypt_start = time.perf_counter()
        bcrypt_found = False
        bcrypt_attempts = 0

        for idx, candidate in enumerate(WORDLIST, start=1):
            if (time.perf_counter() - bcrypt_start) >= BCRYPT_BATTLE_MAX_SECONDS:
                break
            bcrypt_attempts = idx
            cand_bytes, _ = prepare_bcrypt_bytes(candidate)
            matched = bcrypt.checkpw(cand_bytes, target_bcrypt)
            elapsed = max(time.perf_counter() - bcrypt_start, 1e-6)
            yield emit(
                {
                    "type": "bcrypt_progress",
                    "attempts": bcrypt_attempts,
                    "total": total_words,
                    "elapsed_ms": round(elapsed * 1000.0, 1),
                    "hps": round(bcrypt_attempts / elapsed, 2),
                }
            )
            if matched:
                bcrypt_found = True
                break

        bcrypt_elapsed = max(time.perf_counter() - bcrypt_start, 1e-6)
        yield emit(
            {
                "type": "bcrypt_done",
                "found": bcrypt_found,
                "stopped_by_time_cap": not bcrypt_found
                and bcrypt_attempts < total_words,
                "attempts": bcrypt_attempts,
                "total": total_words,
                "elapsed_ms": round(bcrypt_elapsed * 1000.0, 1),
                "hps": round(bcrypt_attempts / bcrypt_elapsed, 2),
            }
        )

        # --- Phase 3: Real machine benchmarks & keyspace estimates ---
        benchmarks = run_machine_benchmark()
        estimates = build_keyspace_estimates(password, benchmarks)
        yield emit(
            {
                "type": "complete",
                "benchmarks": benchmarks,
                "estimates": estimates,
            }
        )

    return Response(
        stream_with_context(generate_events()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    # Strictly bind to localhost only for safety
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
