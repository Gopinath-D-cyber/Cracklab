/**
 * CrackLab frontend controller.
 * Communicates strictly with local Flask endpoints (127.0.0.1) in memory.
 */

const DEMO_PASSWORD = "password123";

const passwordInput = document.getElementById("password-input");
const toggleVisibilityBtn = document.getElementById("toggle-visibility-btn");
const demoModeBtn = document.getElementById("demo-mode-btn");
const battleBtn = document.getElementById("battle-btn");
const resaltBtn = document.getElementById("resalt-btn");
const scaleToggleBtn = document.getElementById("scale-toggle-btn");
const rebenchmarkBtn = document.getElementById("rebenchmark-btn");
const inputErrorEl = document.getElementById("input-error");

let debounceTimer = null;
let battleRunning = false;
let chartInstance = null;
let useLogScale = true;
let lastBenchmarks = [];
let masked = false;

/** Escape text before inserting into HTML strings to avoid XSS. */
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

/** Display or hide an inline error message below the password box. */
function showError(message) {
  if (!message) {
    inputErrorEl.textContent = "";
    inputErrorEl.classList.add("hidden");
    return;
  }
  inputErrorEl.textContent = message;
  inputErrorEl.classList.remove("hidden");
}

/** Format numbers cleanly with locale commas. */
function formatNumber(val) {
  return Number(val).toLocaleString(undefined, { maximumFractionDigits: 1 });
}

/** Update Feature 1 (Strength Analyzer) DOM elements from API payload. */
function renderStrength(strength) {
  const badge = document.getElementById("strength-badge");
  const bar = document.getElementById("strength-bar");

  const widths = [12, 30, 55, 80, 100];
  bar.style.width = `${widths[strength.score] || 12}%`;
  bar.style.backgroundColor = strength.color;

  badge.textContent = `${strength.label} (${strength.score}/4)`;
  badge.className = `pill ${
    strength.score <= 1 ? "pill-danger" : strength.score === 2 ? "pill-warning" : "pill-safe"
  }`;

  document.getElementById("strength-length").textContent = strength.length;
  document.getElementById("strength-guesses").textContent = `10^${strength.guesses_log10}`;
  document.getElementById("strength-leaked").textContent = strength.in_wordlist ? "YES (Found!)" : "No";

  document.getElementById("strength-reasons").innerHTML = strength.reasons
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  document.getElementById("strength-tips").innerHTML = strength.tips
    .map((t) => `<li>${escapeHtml(t)}</li>`)
    .join("");
}

/** Update Feature 2 (Hash Comparison) table from API payload. */
function renderHashes(hashes) {
  const tbody = document.getElementById("hash-table-body");
  tbody.innerHTML = hashes
    .map((item) => {
      const pillClass =
        item.level === "danger" ? "pill-danger" : item.level === "warning" ? "pill-warning" : "pill-safe";
      const noteHtml = item.note ? `<span class="hash-note">${escapeHtml(item.note)}</span>` : "";
      return `
        <tr>
          <td><strong>${escapeHtml(item.algorithm)}</strong></td>
          <td><code>${escapeHtml(item.time_display)}</code></td>
          <td><span class="pill ${pillClass}">${escapeHtml(item.badge)}</span></td>
          <td class="hash-cell">${escapeHtml(item.hash)}${noteHtml}</td>
        </tr>
      `;
    })
    .join("");
}

/** Update Feature 3 (Salt Demo) table from API payload. */
function renderSaltDemo(saltDemo) {
  document.getElementById("salt-explanation").textContent = saltDemo.explanation;
  const tbody = document.getElementById("salt-table-body");
  tbody.innerHTML = saltDemo.rows
    .map((row) => {
      const pillClass = row.identical ? "pill-danger" : "pill-safe";
      const label = row.identical ? "IDENTICAL (Unsafe)" : "DIFFERENT (Salted)";
      return `
        <tr>
          <td><strong>${escapeHtml(row.algorithm)}</strong></td>
          <td class="hash-cell">${escapeHtml(row.hash_1)}</td>
          <td class="hash-cell">${escapeHtml(row.hash_2)}</td>
          <td><span class="pill ${pillClass}">${label}</span></td>
        </tr>
      `;
    })
    .join("");
}

/** Update Feature 5 (Rainbow Table Demo) cards from API payload. */
function renderRainbowTable(data) {
  document.getElementById("rainbow-size").textContent = formatNumber(data.table_size);

  const uBadge = document.getElementById("rainbow-unsalted-badge");
  document.getElementById("rainbow-unsalted-hash").textContent = data.unsalted.hash;
  document.getElementById("rainbow-unsalted-time").textContent = `${data.unsalted.lookup_ms} ms`;

  if (data.unsalted.found) {
    uBadge.textContent = "CRACKED INSTANTLY";
    uBadge.className = "pill pill-danger";
    document.getElementById("rainbow-unsalted-result").textContent = `MATCH -> "${data.unsalted.recovered_password}"`;
  } else {
    uBadge.textContent = "NOT IN 10K TABLE";
    uBadge.className = "pill pill-info";
    document.getElementById("rainbow-unsalted-result").textContent = "Not in bundled 10k table (try 'password123')";
  }

  const sBadge = document.getElementById("rainbow-salted-badge");
  document.getElementById("rainbow-salt-value").textContent = data.salted.salt;
  document.getElementById("rainbow-salted-hash").textContent = data.salted.hash;
  document.getElementById("rainbow-salted-time").textContent = `${data.salted.lookup_ms} ms`;

  sBadge.textContent = data.salted.found ? "FOUND" : "LOOKUP FAILED (SAFE)";
  sBadge.className = data.salted.found ? "pill pill-danger" : "pill pill-safe";
  document.getElementById("rainbow-salted-result").textContent = data.salted.found
    ? "Unexpected match"
    : "MISS — salt broke the precomputed table";
}

/** Render or update Feature 6 (Chart.js Bar Chart) using real benchmark data. */
function renderSpeedChart(benchmarks) {
  if (!benchmarks || benchmarks.length === 0 || typeof Chart === "undefined") {
    return;
  }
  lastBenchmarks = benchmarks;

  const ctx = document.getElementById("speed-chart").getContext("2d");
  const labels = benchmarks.map((b) => b.algorithm);
  const values = benchmarks.map((b) => b.hashes_per_sec);
  const colors = ["#ff4d6d", "#ff7b54", "#ffb703", "#38bdf8", "#00f59b"];

  if (chartInstance) {
    chartInstance.destroy();
  }

  chartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Measured Hashes / Second",
          data: values,
          backgroundColor: colors,
          borderRadius: 6,
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (context) => `${formatNumber(context.raw)} hashes/sec (Measured)`,
          },
        },
      },
      scales: {
        x: {
          ticks: { color: "#cbd5e1", font: { family: "Consolas, monospace", size: 11 } },
          grid: { color: "#1e293b55" },
        },
        y: {
          type: useLogScale ? "logarithmic" : "linear",
          ticks: {
            color: "#94a3b8",
            callback: (val) => formatNumber(val),
          },
          grid: { color: "#1e293b88" },
          title: {
            display: true,
            text: useLogScale ? "Hashes / sec (Log Scale)" : "Hashes / sec (Linear Scale)",
            color: "#94a3b8",
          },
        },
      },
    },
  });
}

/** Update Keyspace & Estimated Crack Time table (Measured vs Estimated). */
function renderEstimates(estimatesPayload) {
  if (!estimatesPayload) return;
  const ks = estimatesPayload.keyspace;
  document.getElementById("keyspace-summary").innerHTML =
    `Length <strong>${ks.length}</strong> &bull; Charset pool <strong>${ks.pool_size}</strong> (${escapeHtml(
      ks.pools.join(", ")
    )}) &bull; Keyspace <code>${escapeHtml(ks.total_combinations_sci)}</code>`;

  const tbody = document.getElementById("estimates-table-body");
  tbody.innerHTML = estimatesPayload.estimates
    .map(
      (row) => `
      <tr>
        <td><strong>${escapeHtml(row.algorithm)}</strong></td>
        <td><code>${formatNumber(row.measured_hps)} / sec</code> <span class="tag-measured">Measured</span></td>
        <td><strong>${escapeHtml(row.estimated_time)}</strong> <span class="tag-estimated">Estimated</span></td>
      </tr>
    `
    )
    .join("");
}

/** Reset UI panels when password input is empty. */
function resetPanelsForEmptyInput() {
  document.getElementById("strength-badge").textContent = "Waiting for input";
  document.getElementById("strength-badge").className = "pill pill-neutral";
  document.getElementById("strength-bar").style.width = "0%";
  document.getElementById("strength-length").textContent = "0";
  document.getElementById("strength-guesses").textContent = "-";
  document.getElementById("strength-leaked").textContent = "-";
  document.getElementById("strength-reasons").innerHTML =
    '<li class="muted">Type a password or click Demo Mode to analyze patterns.</li>';
  document.getElementById("strength-tips").innerHTML =
    '<li class="muted">Actionable suggestions will appear here.</li>';
  document.getElementById("hash-table-body").innerHTML =
    '<tr><td colspan="4" class="muted center">Enter a password to compute hashes.</td></tr>';
  document.getElementById("salt-table-body").innerHTML =
    '<tr><td colspan="4" class="muted center">Enter a password to run the salt comparison.</td></tr>';
}

/** Run Features 1, 2, 3, and 5 for the current password. */
async function analyzeAndRainbow(password) {
  if (!password) {
    showError("");
    resetPanelsForEmptyInput();
    return false;
  }

  try {
    const [analyzeRes, rainbowRes] = await Promise.all([
      fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      }),
      fetch("/api/rainbow-table", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      }),
    ]);

    const analyzeData = await analyzeRes.json();
    if (!analyzeRes.ok) {
      showError(analyzeData.error || "Unable to analyze password.");
      return false;
    }
    showError("");
    renderStrength(analyzeData.strength);
    renderHashes(analyzeData.hashes);
    renderSaltDemo(analyzeData.salt_demo);

    if (rainbowRes.ok) {
      const rainbowData = await rainbowRes.json();
      renderRainbowTable(rainbowData);
    }
    return true;
  } catch (err) {
    showError("Local server connection error. Make sure app.py is running.");
    return false;
  }
}

/** Stream Feature 4 (Live Cracking Battle) + Feature 6 speed update. */
async function runCrackingBattle(password) {
  if (battleRunning) return;
  if (!password) {
    showError("Please enter a password (or click Demo Mode) before launching the battle.");
    return;
  }

  battleRunning = true;
  battleBtn.disabled = true;
  demoModeBtn.disabled = true;
  showError("");

  const md5Status = document.getElementById("md5-battle-status");
  const md5Bar = document.getElementById("md5-progress-bar");
  const md5Timer = document.getElementById("md5-timer");
  const md5Attempts = document.getElementById("md5-attempts");
  const md5Hps = document.getElementById("md5-hps");
  const md5Verdict = document.getElementById("md5-verdict");

  const bcStatus = document.getElementById("bcrypt-battle-status");
  const bcBar = document.getElementById("bcrypt-progress-bar");
  const bcTimer = document.getElementById("bcrypt-timer");
  const bcAttempts = document.getElementById("bcrypt-attempts");
  const bcHps = document.getElementById("bcrypt-hps");
  const bcVerdict = document.getElementById("bcrypt-verdict");

  md5Status.textContent = "ATTACKING...";
  md5Status.className = "pill pill-warning";
  md5Bar.style.width = "0%";
  md5Verdict.textContent = "Scanning common password wordlist against MD5...";

  bcStatus.textContent = "QUEUED";
  bcStatus.className = "pill pill-neutral";
  bcBar.style.width = "0%";
  bcTimer.textContent = "0.0 ms";
  bcAttempts.textContent = "0";
  bcHps.textContent = "-";
  bcVerdict.textContent = "Waiting for MD5 phase to complete...";

  try {
    const res = await fetch("/api/crack-battle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!res.ok) {
      const errData = await res.json();
      showError(errData.error || "Failed to start cracking battle.");
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        const ev = JSON.parse(line);

        if (ev.type === "md5_progress") {
          const pct = Math.min(100, (ev.attempts / Math.max(ev.total, 1)) * 100);
          md5Bar.style.width = `${pct}%`;
          md5Timer.textContent = `${ev.elapsed_ms} ms`;
          md5Attempts.textContent = `${formatNumber(ev.attempts)} / ${formatNumber(ev.total)}`;
          md5Hps.textContent = `${formatNumber(ev.hps)}/s`;
        } else if (ev.type === "md5_done") {
          const pct = ev.found ? 100 : (ev.attempts / Math.max(ev.total, 1)) * 100;
          md5Bar.style.width = `${pct}%`;
          md5Timer.textContent = `${ev.elapsed_ms} ms`;
          md5Attempts.textContent = `${formatNumber(ev.attempts)} / ${formatNumber(ev.total)}`;
          md5Hps.textContent = `${formatNumber(ev.hps)}/s`;

          if (ev.found) {
            md5Status.textContent = "CRACKED!";
            md5Status.className = "pill pill-danger";
            md5Verdict.textContent = `CRACKED in ${ev.elapsed_ms} ms at attempt #${formatNumber(ev.attempts)}!`;
          } else {
            md5Status.textContent = "NOT IN 10K LIST";
            md5Status.className = "pill pill-info";
            md5Verdict.textContent = `Exhausted all ${formatNumber(ev.total)} words in just ${ev.elapsed_ms} ms!`;
          }

          bcStatus.textContent = "ATTACKING...";
          bcStatus.className = "pill pill-warning";
          bcVerdict.textContent = "Testing wordlist against salted bcrypt (capped at 1.8s)...";
        } else if (ev.type === "bcrypt_progress") {
          const pct = Math.min(100, (ev.attempts / Math.max(ev.total, 1)) * 100);
          bcBar.style.width = `${Math.max(pct, 2)}%`;
          bcTimer.textContent = `${ev.elapsed_ms} ms`;
          bcAttempts.textContent = `${formatNumber(ev.attempts)} / ${formatNumber(ev.total)}`;
          bcHps.textContent = `${formatNumber(ev.hps)}/s`;
        } else if (ev.type === "bcrypt_done") {
          const pct = (ev.attempts / Math.max(ev.total, 1)) * 100;
          bcBar.style.width = `${Math.max(pct, 2)}%`;
          bcTimer.textContent = `${ev.elapsed_ms} ms`;
          bcAttempts.textContent = `${formatNumber(ev.attempts)} / ${formatNumber(ev.total)}`;
          bcHps.textContent = `${formatNumber(ev.hps)}/s`;

          if (ev.found) {
            bcStatus.textContent = "CRACKED";
            bcStatus.className = "pill pill-warning";
            bcVerdict.textContent = `Matched in ${ev.elapsed_ms} ms after ${ev.attempts} attempts.`;
          } else {
            bcStatus.textContent = "SURVIVED WINDOW";
            bcStatus.className = "pill pill-safe";
            const estAllSec = ev.total / Math.max(ev.hps, 0.1);
            bcVerdict.textContent = `Stopped at ${ev.elapsed_ms} ms cap: only ${ev.attempts} of ${formatNumber(
              ev.total
            )} tested (~${Math.round(estAllSec / 60)} min needed just for this 10k list!).`;
          }
        } else if (ev.type === "complete") {
          renderSpeedChart(ev.benchmarks);
          renderEstimates(ev.estimates);
        }
      }
    }
  } catch (err) {
    showError("Cracking battle stream interrupted.");
  } finally {
    battleRunning = false;
    battleBtn.disabled = false;
    demoModeBtn.disabled = false;
  }
}

/** Fetch initial machine benchmarks on page load so the chart is live right away. */
async function loadInitialBenchmark(password = "") {
  try {
    const opts = password
      ? {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        }
      : { method: "GET" };
    const res = await fetch("/api/benchmark", opts);
    if (!res.ok) return;
    const data = await res.json();
    renderSpeedChart(data.benchmarks);
    if (data.estimates) {
      renderEstimates(data.estimates);
    }
  } catch (err) {
    // Ignore transient startup load failure
  }
}

// --- Event Wiring ---
passwordInput.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    analyzeAndRainbow(passwordInput.value);
  }, 150);
});

toggleVisibilityBtn.addEventListener("click", () => {
  masked = !masked;
  passwordInput.type = masked ? "password" : "text";
  toggleVisibilityBtn.textContent = masked ? "Show" : "Hide";
});

document.querySelectorAll(".chip[data-preset]").forEach((chip) => {
  chip.addEventListener("click", async () => {
    const preset = chip.getAttribute("data-preset") || "";
    passwordInput.value = preset;
    await analyzeAndRainbow(preset);
    await loadInitialBenchmark(preset);
  });
});

battleBtn.addEventListener("click", async () => {
  const pw = passwordInput.value;
  const ok = await analyzeAndRainbow(pw);
  if (ok) {
    await runCrackingBattle(pw);
  }
});

resaltBtn.addEventListener("click", async () => {
  if (!passwordInput.value) {
    showError("Enter a password first to test a new random salt.");
    return;
  }
  const res = await fetch("/api/rainbow-table", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: passwordInput.value }),
  });
  if (res.ok) {
    renderRainbowTable(await res.json());
  }
});

scaleToggleBtn.addEventListener("click", () => {
  useLogScale = !useLogScale;
  scaleToggleBtn.textContent = useLogScale ? "Scale: Log" : "Scale: Linear";
  renderSpeedChart(lastBenchmarks);
});

rebenchmarkBtn.addEventListener("click", async () => {
  rebenchmarkBtn.disabled = true;
  rebenchmarkBtn.textContent = "Measuring...";
  await loadInitialBenchmark(passwordInput.value);
  rebenchmarkBtn.textContent = "Re-Benchmark";
  rebenchmarkBtn.disabled = false;
});

demoModeBtn.addEventListener("click", async () => {
  passwordInput.value = DEMO_PASSWORD;
  masked = false;
  passwordInput.type = "text";
  toggleVisibilityBtn.textContent = "Hide";

  const ok = await analyzeAndRainbow(DEMO_PASSWORD);
  if (ok) {
    document.getElementById("battle-section").scrollIntoView({ behavior: "smooth", block: "nearest" });
    await runCrackingBattle(DEMO_PASSWORD);
  }
});

// Load real CPU benchmark chart immediately on startup
window.addEventListener("DOMContentLoaded", () => {
  loadInitialBenchmark();
});
