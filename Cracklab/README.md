# CrackLab

**CrackLab** is an offline, hackathon-ready security demo that visually shows why weak passwords and fast hashing fail — and how salts and slow, memory-hard password hashes protect users.

> **Educational demo. Do not enter your real passwords.**  
> All analysis, hashing, and cracking runs 100% locally in memory on `127.0.0.1` with zero logging, zero database storage, and zero external internet requests.

---

## Setup Steps

1. **Navigate to the project folder:**
   ```powershell
   cd d:\Cracklab
   ```
2. **Create and activate a Python virtual environment (already included if using `.venv`):**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
4. **Verify offline assets exist:**
   - `static/js/chart.umd.min.js` (locally bundled Chart.js)
   - `data/wordlist.txt` (10,000 common passwords)

---

## How to Run the Demo

Start the Flask server (binds strictly to `127.0.0.1:5000`):

```powershell
.\.venv\Scripts\python.exe app.py
```

Then open your browser to:

```text
http://127.0.0.1:5000
```

### 30-Second Stage Presentation Tip
Click the green **`▶ Run Demo Mode (password123)`** button at the top right. It automatically populates `"password123"`, runs all strength/hash/salt/rainbow-table checks, and launches the live MD5 vs. bcrypt cracking battle so you can present smoothly without typing.

---

## How Each Feature Works

1. **Password Strength Analyzer**  
   As you type, the app sends your test input to `/api/analyze` in memory and runs `zxcvbn` alongside custom pattern checks. It detects short passwords, dictionary words, keyboard walks (like `qwerty`), repeated characters (like `aaaaaa`), and leaked-style patterns (like `word123`), then gives 2–3 tailored improvement tips.

2. **Hash Comparison (Real Compute Time)**  
   The backend hashes your input with five algorithms — **MD5**, **SHA-1**, **SHA-256**, **bcrypt**, and **Argon2id** — and uses Python's high-precision `time.perf_counter()` timer to display how many microseconds or milliseconds each one actually took on your CPU.

3. **Salt Demo (Same Password Hashed Twice)**  
   The server hashes the exact same password twice in a row. Unsalted MD5 and SHA-256 produce identical digests every time, while `bcrypt` and `Argon2id` automatically generate a fresh random salt per hash, producing two completely different outputs.

4. **Live Cracking Battle & Keyspace Projection**  
   Using the bundled 10,000-password list (`data/wordlist.txt`), the server streams a real dictionary attack against an **MD5** hash (scanning thousands of words in milliseconds) and then runs the exact same attack against **bcrypt** (capped at 1.8 seconds so the UI stays responsive, showing how few attempts/second succeed). Finally, it measures your CPU's real speed for all five algorithms and multiplies by the password's estimated keyspace to label **Measured** speeds vs. **Estimated** brute-force times.

5. **Rainbow Table Lookup Demo**  
   When the server starts, it precomputes an in-memory lookup dictionary mapping all 10,000 common passwords to their unsalted MD5 hashes. Looking up an unsalted MD5 hash succeeds in a fraction of a millisecond (`O(1)`). Adding a random salt changes the input to `salt + password`, causing the precomputed table lookup to miss completely.

6. **Speed Chart**  
   Powered by a locally bundled copy of Chart.js, this bar chart plots your CPU's real measured hashes/second across all five algorithms. You can switch between **Log Scale** (to inspect every bar clearly) and **Linear Scale** (to visualize the staggering speed gap).

7. **"Why This Matters" Panels & Breach Context**  
   Every section includes a concise takeaway, anchored by the **LinkedIn 2012 unsalted SHA-1 leak** (~6.5M hashes stolen, ~90% cracked in days).

---

## Judge Q&A

### 1. Why is bcrypt slow on purpose?
Normal hash functions like MD5 and SHA-256 were designed to verify large files as fast as possible. For passwords, speed is a flaw because an attacker with a stolen database can test billions of guesses per second on a GPU. `bcrypt` uses an adjustable **cost factor** (work factor) that intentionally forces each hash check to take tens or hundreds of milliseconds — barely noticeable during a single user login, but devastatingly expensive for an attacker trying millions of guesses.

### 2. What is a salt?
A **salt** is a unique, random string added to each user's password before hashing (for example, `hash(salt + password)`). Because every user gets a different salt, two people with the exact same password end up with completely different hashes in the database. This stops attackers from spotting shared passwords and prevents precomputed lookup attacks.

### 3. Why is MD5 unsafe?
MD5 is unsafe for two reasons:
1. **Cryptographically broken:** Researchers can intentionally create MD5 collisions (two different inputs that produce the same hash).
2. **Way too fast:** A single modern GPU can compute tens of billions of MD5 hashes per second, meaning weak and medium passwords can be brute-forced almost effortlessly.

### 4. What is a rainbow table?
A **rainbow table** is a giant precomputed cheat sheet of `(hash -> password)` pairs generated ahead of time for common passwords and character combinations. If a database stores unsalted hashes, an attacker doesn't even need to crack them one by one — they simply look up the leaked hash in the table and recover the password instantly. Adding a unique random salt defeats rainbow tables completely.
