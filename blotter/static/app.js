"use strict";

// Everything shown from a scan goes in with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
// The per-start code Blotter put in the page; every request carries it.
const API_HEADERS = { "X-Blotter-Token": document.querySelector('meta[name="blotter-token"]')?.content || "" };
let lastScan = null;      // {file} or {path}: what "Check again" repeats
let currentJob = null;
let pollTimer = null;
let status = null;

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  const units = ["KB", "MB", "GB"];
  let n = bytes / 1024, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]} (${bytes.toLocaleString()} bytes)`;
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...API_HEADERS, ...(options.headers || {}) } });
  let body = {};
  try { body = await response.json(); } catch (_) { /* empty answer */ }
  if (!response.ok) throw new Error(body.error || `Blotter answered with HTTP ${response.status}.`);
  return body;
}

const post = (path, data) => api(path, {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}),
});

/* ---------- settings ---------- */

function showKeyState(keys) {
  for (const row of document.querySelectorAll(".key-row")) {
    const set = Boolean(keys[row.dataset.service]);
    row.querySelector(".key-state").textContent = set ? "saved" : "not set";
    row.querySelector(".remove").hidden = !set;
    row.querySelector("input").placeholder = set ? "saved (type a new one to replace it)" : "not set";
  }
}

const CLAMAV_WORDS = {
  ready: "Running", starting: "Starting (loading its signatures)", updating: "Downloading its signatures",
  off: "Turned off", not_installed: "Not set up yet (see README.txt, \"ClamAV\")", failed: "Couldn't start",
  stopped: "Not running",
};

function showStatus(s) {
  status = s;
  showKeyState(s.keys);
  $("clamav-on").checked = s.settings.clamav;
  const c = s.clamav;
  $("clamav-state").textContent = `${CLAMAV_WORDS[c.state] || c.state}${c.message ? ": " + c.message : ""}`;
  const SANDBOX_WORDS = {
    appcontainer: "Windows AppContainer: checks that read the file have no network and can't open your files.",
    "low-integrity": "Low-integrity box: checks can't change anything on the PC, but could read files and reach the network.",
    "job-only": "Time and memory limits only (no sandbox could start).",
  };
  $("sandbox-state").textContent = (SANDBOX_WORDS[s.sandbox.mode] || "Starting…") +
    (s.sandbox.why ? ` (${s.sandbox.why})` : "");
  const r = s.rules;
  $("rules-state").textContent = r.updating ? "Updating…" :
    `YARA Forge: ${r.yara_forge ? "from " + r.yara_forge : "not downloaded"}. capa: ${r.capa ? "ready" : "not downloaded"}.` +
    (r.last_update && r.last_update.length ? " Last update: " + r.last_update.join(" ") : "");
  $("trusted").replaceChildren(...(s.trusted.length ? s.trusted.map(trustedRow) : [el("li", "None yet.", "hint")]));
  $("quarantined").replaceChildren(...(s.quarantine.length ? s.quarantine.map(quarantineRow) : [el("li", "Empty.", "hint")]));
  const rows = [];
  for (const [host, why] of Object.entries({ ...s.network.lookups })) rows.push(el("li", `${host} (lookup): ${why}`));
  for (const [host, why] of Object.entries(s.network.downloads)) rows.push(el("li", `${host} (download): ${why}`));
  $("addresses").replaceChildren(...rows);
}

function trustedRow(t) {
  const li = el("li");
  li.append(el("span", `${t.name} · ${new Date(t.added_at * 1000).toLocaleDateString()} `));
  const b = el("button", "Stop trusting", "link");
  b.addEventListener("click", async () => { await post(`/api/trusted/${t.sha256}/remove`); refresh(); });
  li.append(b);
  return li;
}

function quarantineRow(q) {
  const li = el("li");
  li.append(el("span", `${q.name} (from ${q.original}) `));
  const b = el("button", "Put back", "link");
  b.addEventListener("click", async () => {
    try { await post(`/api/quarantine/${q.id}/restore`); } catch (e) { alert(e.message); }
    refresh();
  });
  li.append(b);
  return li;
}

function openSettings(open, welcome = false) {
  $("settings").hidden = !open;
  $("welcome").hidden = !welcome;
  $("skip").hidden = !welcome;
  $("settings-title").textContent = welcome ? "Set up (optional)" : "Settings";
  $("keys-message").textContent = "";
  if (open) { refresh(); $("settings").scrollIntoView({ block: "nearest" }); }
}

async function finishSetup() {
  try { await post("/api/settings", { setup_done: true }); } catch (_) { /* not important */ }
}

async function saveKeys(event) {
  event.preventDefault();
  const message = $("keys-message");
  let saved = 0;
  try {
    for (const row of document.querySelectorAll(".key-row")) {
      const input = row.querySelector("input");
      if (!input.value.trim()) continue;
      const body = await post("/api/keys", { service: row.dataset.service, key: input.value.trim() });
      input.value = "";
      saved++;
      showKeyState(body.keys);
    }
    message.textContent = saved ? "Saved in Windows Credential Manager." : "Type a key first, or skip.";
    if (saved && !$("welcome").hidden) { await finishSetup(); openSettings(false); }
  } catch (error) {
    message.textContent = error.message;
  }
}

async function removeKey(row) {
  try {
    const body = await post(`/api/keys/${row.dataset.service}/remove`);
    showKeyState(body.keys);
    $("keys-message").textContent = "Key removed.";
  } catch (error) {
    $("keys-message").textContent = error.message;
  }
}

async function refresh() {
  try { showStatus(await api("/api/status")); } catch (_) { /* Blotter stopped */ }
}

/* ---------- scanning ---------- */

async function scanFile(file, force = false) {
  lastScan = { file };
  showRunning(file.name);
  try {
    const job = await api("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-File-Name": encodeURIComponent(file.name),
        ...(force ? { "X-Force": "1" } : {}),
      },
      body: file,
    });
    render(job);
    poll(job.id);
  } catch (error) {
    showProblem(file.name, error.message.includes("Failed to fetch")
      ? "The file couldn't be read. If you just downloaded it, Microsoft Defender may already have removed it."
      : error.message);
  }
}

async function scanPath(path, force = false) {
  lastScan = { path };
  showRunning(path);
  try {
    const job = await post("/api/scan-path", { path, force });
    render(job);
    poll(job.id);
  } catch (error) {
    showProblem(path, error.message);
  }
}

function poll(id) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const job = await api(`/api/jobs/${id}`);
      render(job);
      if (job.state !== "done") poll(id);
    } catch (error) {
      showProblem("", error.message);
    }
  }, 700);
}

function showRunning(name) {
  clearTimeout(pollTimer);
  currentJob = null;
  $("result").hidden = false;
  $("card").className = "card running";
  $("card-file").textContent = name;
  $("card-verdict").textContent = "Checking…";
  $("card-summary").textContent = "Reading the file and asking each check.";
  $("card-reasons").replaceChildren();
  $("progress").replaceChildren();
  $("card-actions").hidden = true;
  $("card-message").textContent = "";
  $("details").hidden = true;
}

function showProblem(name, text) {
  $("card").className = "card v-couldnt_check";
  $("card-file").textContent = name;
  $("card-verdict").textContent = "Couldn't check";
  $("card-summary").textContent = text;
  $("card-reasons").replaceChildren();
  $("progress").replaceChildren();
  $("card-actions").hidden = true;
  $("details").hidden = true;
}

function render(job) {
  currentJob = job;
  const done = job.state === "done";
  $("card-file").textContent = `${job.name} · ${formatSize(job.size)}`;
  $("card").className = done ? `card v-${job.verdict.verdict}` : "card running";
  $("card-verdict").textContent = done ? job.verdict.title : "Checking…";
  $("card-summary").textContent = done ? job.verdict.summary : "Each check reports as soon as it finishes.";
  $("card-reasons").replaceChildren(...(done ? job.verdict.reasons.map((r) => el("li", r)) : []));
  $("progress").replaceChildren(...(done ? [] : job.checks.map((c) => {
    const label = c.state === "done" ? "done" : c.state === "running" ? "working…" : "waiting…";
    return el("li", `${c.name}: ${label}`, c.state === "done" ? "done" : "");
  })));

  $("card-actions").hidden = false;
  $("open-vt").href = `https://www.virustotal.com/gui/file/${job.sha256}`;
  $("vt-state").textContent = vtState(job.checks.find((c) => c.id === "virustotal"));
  $("trust").hidden = !done;
  $("trust").textContent = job.trusted ? "Stop trusting this file" : "Trust this file";
  $("quarantine").hidden = !(done && job.source_path);
  $("password-form").hidden = !(done && job.needs_password);
  $("password-hint").hidden = !(done && job.needs_password);

  $("details").hidden = false;
  $("d-sha").textContent = job.sha256;
  $("d-size").textContent = formatSize(job.size);
  $("d-where").textContent = job.source_path || "a copy (dropped on the page or chosen in the browser)";
  $("d-checks").replaceChildren(...job.checks.map(renderCheck));
  const anyCached = job.checks.some((c) => c.cached_at);
  $("again").hidden = !(done && anyCached);
  $("again-hint").hidden = !(done && anyCached);
}

// One short line next to "Open on VirusTotal". Without a key it says "not checked", never "never seen".
function vtState(check) {
  if (!check) return "";
  if (check.state !== "done") return "VirusTotal: checking…";
  const f = check.findings[0] || {};
  const d = f.details || {};
  if (d.not_checked === "no_key") return "VirusTotal: not checked (no key)";
  if ((f.signals || []).includes("unknown_online")) return "VirusTotal: has never seen this file";
  if (d.engines) return `VirusTotal: ${d.malicious} of ${d.engines} engines flag it`;
  if (f.level === "error") return "VirusTotal: couldn't check this time";
  return "";
}

function renderCheck(check) {
  const box = el("section", null, "check");
  box.append(el("h3", check.name));
  if (check.cached_at) {
    const when = new Date(check.cached_at * 1000).toLocaleString();
    box.append(el("p", `Remembered answer from ${when} (no quota used).`, "hint"));
  }
  if (check.state !== "done") box.append(el("p", "Still working…", "hint"));
  for (const finding of check.findings) {
    box.append(el("p", finding.text, finding.level === "skipped" ? "hint" : null));
    const d = finding.details || {};
    if (d.flagged && d.flagged.length) {
      const table = el("table");
      const head = table.insertRow();
      for (const h of ["Engine", "Says", "Name"]) head.append(el("th", h));
      for (const row of d.flagged) {
        const tr = table.insertRow();
        tr.append(el("td", row.engine), el("td", row.category), el("td", row.result || ""));
      }
      box.append(table);
    }
    const facts = [];
    if (d.signature && typeof d.signature === "string") facts.push(`Malware family: ${d.signature}`);
    if (d.signature && d.signature.signer) facts.push(`Signed by: ${d.signature.signer}`);
    if (d.rule) facts.push(`Rule: ${d.rule}${d.source ? " (" + d.source + ")" : ""}`);
    if (d.tags && d.tags.length) facts.push(`Tags: ${d.tags.join(", ")}`);
    if (d.file_type) facts.push(`File type: ${d.file_type}`);
    if (d.names && d.names.length) facts.push(`Known names: ${d.names.join(", ")}`);
    if (d.scanner) facts.push(`Scanner: ${d.scanner}`);
    if (d.exit_code != null) facts.push(`Exit code: ${d.exit_code}`);
    for (const fact of facts) box.append(el("p", fact, "hint"));
    if (d.link) {
      const a = el("a", "Open this file's page");
      a.href = d.link;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      box.append(a);
    }
    if (d.output) {
      const more = el("details");
      more.append(el("summary", "Scanner output"), el("pre", d.output));
      box.append(more);
    }
  }
  return box;
}

async function toggleTrust() {
  if (!currentJob) return;
  try {
    const job = await post(`/api/jobs/${currentJob.id}/trust`, { trusted: !currentJob.trusted });
    render(job);
    $("card-message").textContent = job.trusted
      ? "Trusted. If this file changes, even by one byte, the trust ends."
      : "No longer trusted.";
  } catch (error) {
    $("card-message").textContent = error.message;
  }
}

async function tryPassword(event) {
  event.preventDefault();
  const input = $("archive-password");
  if (!currentJob || !input.value) return;
  try {
    const job = await post(`/api/jobs/${currentJob.id}/password`, { password: input.value });
    input.value = "";
    render(job);
    poll(job.id);
  } catch (error) {
    $("card-message").textContent = error.message;
  }
}

async function quarantineFile() {
  if (!currentJob || !currentJob.source_path) return;
  if (!confirm(`Move ${currentJob.source_path} into Blotter's quarantine? You can put it back from Settings.`)) return;
  try {
    const body = await post(`/api/jobs/${currentJob.id}/quarantine`);
    render(body.job);
    $("card-message").textContent = `Moved to quarantine as ${body.entry.stored}.`;
  } catch (error) {
    $("card-message").textContent = error.message;
  }
}

/* ---------- drop zone ---------- */

function pickFrom(dataTransfer) {
  const items = [...(dataTransfer.items || [])].filter((i) => i.kind === "file");
  if (items.length && items[0].webkitGetAsEntry && items[0].webkitGetAsEntry()?.isDirectory) {
    showProblem("", "That's a folder. Blotter checks one file at a time.");
    return null;
  }
  return dataTransfer.files[0] || null;
}

function setup() {
  const drop = $("drop");
  const picker = $("picker");
  drop.addEventListener("click", () => picker.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  picker.addEventListener("change", () => { if (picker.files[0]) scanFile(picker.files[0]); picker.value = ""; });
  for (const name of ["dragenter", "dragover"]) {
    document.addEventListener(name, (e) => { e.preventDefault(); drop.classList.add("over"); });
  }
  for (const name of ["dragleave", "dragend"]) {
    document.addEventListener(name, (e) => { if (!e.relatedTarget) drop.classList.remove("over"); });
  }
  document.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const file = pickFrom(e.dataTransfer);
    if (file) scanFile(file);
  });

  $("pick-local").addEventListener("click", async () => {
    try {
      const { path } = await post("/api/pick");
      if (path) scanPath(path);
    } catch (error) { showProblem("", error.message); }
  });
  $("path-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const path = $("path-input").value.trim().replace(/^"|"$/g, "");
    if (path) scanPath(path);
  });

  $("again").addEventListener("click", () => {
    if (lastScan && lastScan.file) scanFile(lastScan.file, true);
    else if (lastScan && lastScan.path) scanPath(lastScan.path, true);
  });
  $("trust").addEventListener("click", toggleTrust);
  $("quarantine").addEventListener("click", quarantineFile);
  $("password-form").addEventListener("submit", tryPassword);
  $("eicar").addEventListener("click", () => {
    // Built in memory from pieces, so this script itself never looks like the test file.
    const text = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"].join("");
    scanFile(new File([text], "eicar.com"));
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  $("settings-button").addEventListener("click", () => openSettings($("settings").hidden));
  $("settings-close").addEventListener("click", () => openSettings(false));
  $("skip").addEventListener("click", async () => { await finishSetup(); openSettings(false); });
  $("keys-form").addEventListener("submit", saveKeys);
  for (const row of document.querySelectorAll(".key-row")) {
    row.querySelector(".remove").addEventListener("click", () => removeKey(row));
  }
  $("clamav-on").addEventListener("change", async (e) => {
    await post("/api/settings", { clamav: e.target.checked });
    setTimeout(refresh, 500);
  });
  $("update-rules").addEventListener("click", async () => {
    await post("/api/updates");
    refresh();
    const wait = setInterval(async () => { await refresh(); if (status && !status.rules.updating) clearInterval(wait); }, 2000);
  });

  api("/api/status").then((s) => {
    showStatus(s);
    // First run: a short, skippable setup.
    if (!s.settings.setup_done) openSettings(true, true);
    if (!s.key_store_ok) $("keys-message").textContent = "Windows Credential Manager isn't available, so keys can't be saved.";
  }).catch(() => {});
}

setup();
