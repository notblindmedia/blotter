"use strict";

// Everything shown from a scan goes in with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
const API_HEADERS = { "X-Blotter": "1" };
let lastFile = null;
let pollTimer = null;

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

/* ---------- keys ---------- */

function showKeyState(keys) {
  for (const row of document.querySelectorAll(".key-row")) {
    const set = Boolean(keys[row.dataset.service]);
    row.querySelector(".key-state").textContent = set ? "saved" : "not set";
    row.querySelector(".remove").hidden = !set;
    row.querySelector("input").placeholder = set ? "saved (type a new one to replace it)" : "not set";
  }
}

function openKeys(open) {
  $("keys").hidden = !open;
  $("keys-message").textContent = "";
  if (open) $("keys").scrollIntoView({ block: "nearest" });
}

async function saveKeys(event) {
  event.preventDefault();
  const message = $("keys-message");
  let saved = 0;
  try {
    for (const row of document.querySelectorAll(".key-row")) {
      const input = row.querySelector("input");
      if (!input.value.trim()) continue;
      const body = await api("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ service: row.dataset.service, key: input.value.trim() }),
      });
      input.value = "";
      saved++;
      showKeyState(body.keys);
    }
    message.textContent = saved ? "Saved in Windows Credential Manager." : "Type a key first.";
  } catch (error) {
    message.textContent = error.message;
  }
}

async function removeKey(row) {
  try {
    const body = await api(`/api/keys/${row.dataset.service}`, { method: "DELETE" });
    showKeyState(body.keys);
    $("keys-message").textContent = "Key removed.";
  } catch (error) {
    $("keys-message").textContent = error.message;
  }
}

/* ---------- scanning ---------- */

async function scanFile(file, force = false) {
  lastFile = file;
  clearTimeout(pollTimer);
  showRunning(file);
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

function poll(id) {
  pollTimer = setTimeout(async () => {
    try {
      const job = await api(`/api/jobs/${id}`);
      render(job);
      if (job.state !== "done") poll(id);
    } catch (error) {
      showProblem(lastFile ? lastFile.name : "", error.message);
    }
  }, 600);
}

function showRunning(file) {
  $("result").hidden = false;
  const card = $("card");
  card.className = "card running";
  $("card-file").textContent = file.name;
  $("card-verdict").textContent = "Checking…";
  $("card-summary").textContent = "Reading the file and asking each check.";
  $("card-reasons").replaceChildren();
  $("progress").replaceChildren();
  $("details").hidden = true;
}

function showProblem(name, text) {
  const card = $("card");
  card.className = "card v-couldnt_check";
  $("card-file").textContent = name;
  $("card-verdict").textContent = "Couldn't check";
  $("card-summary").textContent = text;
  $("card-reasons").replaceChildren();
  $("progress").replaceChildren();
  $("details").hidden = true;
}

function render(job) {
  const card = $("card");
  const done = job.state === "done";
  $("card-file").textContent = `${job.name} · ${formatSize(job.size)}`;
  card.className = done ? `card v-${job.verdict.verdict}` : "card running";
  $("card-verdict").textContent = done ? job.verdict.title : "Checking…";
  $("card-summary").textContent = done ? job.verdict.summary : "Each check reports as soon as it finishes.";

  const reasons = $("card-reasons");
  reasons.replaceChildren(...(done ? job.verdict.reasons.map((r) => el("li", r)) : []));

  const progress = $("progress");
  progress.replaceChildren(...(done ? [] : job.checks.map((c) => {
    const label = c.state === "done" ? "done" : c.state === "running" ? "working…" : "waiting…";
    return el("li", `${c.name}: ${label}`, c.state === "done" ? "done" : "");
  })));

  $("details").hidden = false;
  $("d-sha").textContent = job.sha256;
  $("d-size").textContent = formatSize(job.size);
  $("d-checks").replaceChildren(...job.checks.map(renderCheck));
  const anyCached = job.checks.some((c) => c.cached_at);
  $("again").hidden = !(done && anyCached);
  $("again-hint").hidden = !(done && anyCached);
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
    box.append(el("p", finding.text));
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
    if (d.signature) facts.push(`Malware family: ${d.signature}`);
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

  $("again").addEventListener("click", () => { if (lastFile) scanFile(lastFile, true); });
  $("eicar").addEventListener("click", () => {
    // Built in memory from pieces, so this script itself never looks like the test file.
    const text = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"].join("");
    scanFile(new File([text], "eicar.com"));
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  $("keys-button").addEventListener("click", () => openKeys($("keys").hidden));
  $("keys-close").addEventListener("click", () => openKeys(false));
  $("keys-form").addEventListener("submit", saveKeys);
  for (const row of document.querySelectorAll(".key-row")) {
    row.querySelector(".remove").addEventListener("click", () => removeKey(row));
  }

  api("/api/status").then((status) => {
    showKeyState(status.keys);
    // First run: ask for the keys until both are set.
    if (!status.keys.virustotal || !status.keys.malwarebazaar) openKeys(true);
    if (!status.key_store_ok) $("keys-message").textContent = "Windows Credential Manager isn't available, so keys can't be saved.";
  }).catch(() => {});
}

setup();
