"use strict";

// PRIVACY: repository content is fetched directly from api.github.com and scanned in this browser.
// No repository content or token is sent to a relay server, logged, exported, or stored outside memory.

const state = { repo: null, token: "", branch: "", files: [], scanFiles: [], findings: [], rate: null, scanned: 0 };
const TEXT_EXTENSIONS = new Set(["js","ts","jsx","tsx","py","java","rb","go","php","yml","yaml","json","env","properties","xml","html","sh","config","txt","md"]);
const SECRET_NAMES = new Set([".env", "dockerfile", "docker-compose.yml", "docker-compose.yaml"]);
const SKIP_DIRS = /(^|\/)(node_modules|dist|build|\.git|vendor|coverage|\.next|target)(\/|$)/i;
const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|.*\.lock)$/i;
const SKIP_ASSET = /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|mp3|mp4|mov|avi|wav|woff2?|ttf|otf|eot|zip|gz|pdf|exe|dll|so)$/i;

function parseRepo(value) {
  const input = String(value || "").trim().replace(/\/+$/, "");
  if (!input) return null;
  if (/^[^/\\\s]+\/[^/\\\s]+$/.test(input)) { const [owner, repo] = input.split("/"); return owner && repo ? { owner, repo: repo.replace(/\.git$/i, "") } : null; }
  try { const url = new URL(input); if (url.hostname.toLowerCase() !== "github.com") return null; const parts = url.pathname.split("/").filter(Boolean); return parts.length === 2 ? { owner: parts[0], repo: parts[1].replace(/\.git$/i, "") } : null; } catch (_) { return null; }
}
function headers() { const h = { Accept: "application/vnd.github+json" }; if (state.token) h.Authorization = `Bearer ${state.token}`; return h; }
function updateRate(response) { const remaining = response.headers.get("X-RateLimit-Remaining"); if (remaining !== null) state.rate = { remaining: Number(remaining), limit: Number(response.headers.get("X-RateLimit-Limit") || 60), reset: Number(response.headers.get("X-RateLimit-Reset") || 0) }; }
function rateText() { if (!state.rate) return "GitHub API rate limit: checking…"; const reset = state.rate.reset ? new Date(state.rate.reset * 1000).toLocaleTimeString() : "unknown"; return `GitHub API: ${state.rate.remaining}/${state.rate.limit} requests remaining · reset ${reset}`; }
function setStatus(text) { document.getElementById("status").textContent = text; }
function setProgress(percent, label) { document.getElementById("progress-wrap").hidden = false; document.getElementById("progress").value = percent; document.getElementById("progress-count").textContent = `${Math.round(percent)}%`; document.getElementById("progress-label").textContent = label; }
function setBusy(busy) { document.getElementById("scan-button").disabled = busy; }
function isCandidate(path) { if (SKIP_DIRS.test(path) || SKIP_FILE.test(path) || SKIP_ASSET.test(path)) return false; const name = path.split("/").pop().toLowerCase(); if (SECRET_NAMES.has(name)) return true; const dot = name.lastIndexOf("."); return dot > 0 && TEXT_EXTENSIONS.has(name.slice(dot + 1)); }
async function githubFetch(url) {
  let response; try { response = await fetch(url, { headers: headers() }); } catch (cause) { throw new Error(`Network failure while contacting GitHub: ${cause.message}`); }
  updateRate(response);
  if (!response.ok) { if (response.status === 404) throw new Error("Repository not found or is not public."); if (response.status === 403 && state.rate?.remaining === 0) throw new Error(`GitHub API rate limit exceeded. Reset time: ${new Date(state.rate.reset * 1000).toLocaleString()}.`); throw new Error(`GitHub API error (${response.status}).`); }
  return response.json();
}
async function fetchFileTree() {
  const base = `https://api.github.com/repos/${encodeURIComponent(state.repo.owner)}/${encodeURIComponent(state.repo.repo)}`;
  const meta = await githubFetch(base); state.branch = meta.default_branch;
  const tree = await githubFetch(`${base}/git/trees/${encodeURIComponent(state.branch)}?recursive=1`);
  state.files = (tree.tree || []).filter(item => item.type === "blob" && isCandidate(item.path));
  return state.files;
}
function decodeBase64Utf8(value) { const binary = atob(String(value).replace(/\s/g, "")); const bytes = Uint8Array.from(binary, char => char.charCodeAt(0)); return new TextDecoder("utf-8").decode(bytes); }
async function fetchCandidateContents(files) {
  const base = `https://api.github.com/repos/${encodeURIComponent(state.repo.owner)}/${encodeURIComponent(state.repo.repo)}/contents/`;
  const usable = files.filter(file => Number(file.size || 0) <= 1024 * 1024);
  state.scanFiles = [];
  for (let index = 0; index < usable.length; index += 1) {
    const file = usable[index];
    setProgress(5 + ((index / Math.max(usable.length, 1)) * 90), `Scanning file ${index + 1} of ${usable.length}: ${file.path}`);
    setStatus(`${file.path} · ${rateText()}`);
    const data = await githubFetch(`${base}${file.path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(state.branch)}`);
    if (data.type !== "file" || !data.content) continue;
    state.scanFiles.push({ path: file.path, size: file.size, text: decodeBase64Utf8(data.content) });
    state.scanned += 1;
  }
  return state.scanFiles;
}
function lineNumber(text, offset) { return text.slice(0, offset).split(/\r?\n/).length; }
function githubFileUrl(path, line) { return `https://github.com/${encodeURIComponent(state.repo.owner)}/${encodeURIComponent(state.repo.repo)}/blob/${encodeURIComponent(state.branch)}/${path.split("/").map(encodeURIComponent).join("/")}#L${line}`; }
function scanContents() {
  state.findings = [];
  for (const file of state.scanFiles) {
    const detections = window.secretSweepPatterns.detectSecrets(file.text);
    for (const detection of detections) {
      const line = lineNumber(file.text, detection.start);
      state.findings.push({ path: file.path, line, pattern: detection.pattern, confidence: detection.confidence, preview: window.secretSweepPatterns.redactPreview(detection.value), url: githubFileUrl(file.path, line) });
    }
  }
  return state.findings;
}

const form = document.getElementById("scan-form");
const repoInput = document.getElementById("repo-input");
const tokenInput = document.getElementById("token-input");
const error = document.getElementById("repo-error");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const parsed = parseRepo(repoInput.value);
  if (!parsed) { error.hidden = false; error.textContent = "Enter a valid GitHub repository as owner/repo or a github.com repository URL."; repoInput.focus(); return; }
  error.hidden = true; state.repo = parsed; state.token = tokenInput.value; state.findings = []; state.scanned = 0;
  setBusy(true); document.getElementById("results-section").hidden = true;
  try {
    setProgress(2, "Fetching repository metadata…");
    const files = await fetchFileTree();
    if (!files.length) throw new Error("No scannable text files were found in this repository.");
    await fetchCandidateContents(files);
    setProgress(96, "Checking fetched files for obvious secrets…");
    scanContents();
    setProgress(100, "Scan complete."); setStatus(`Scanned ${state.scanFiles.length} files · ${state.findings.length} finding${state.findings.length === 1 ? "" : "s"} · ${rateText()}`);
    document.getElementById("results-section").hidden = false;
    if (typeof window.renderResults === "function") window.renderResults();
  } catch (cause) { setStatus(cause.message); }
  finally { setBusy(false); }
});
window.secretSweep = { state, parseRepo, isCandidate, fetchFileTree, fetchCandidateContents, scanContents, lineNumber };
