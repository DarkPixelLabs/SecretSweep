"use strict";

// PRIVACY: repository content is fetched directly from api.github.com and scanned in this browser.
// No repository content or token is sent to a relay server, logged, exported, or stored outside memory.

const state = { repo: null, token: "", branch: "", files: [], findings: [], rate: null, scanned: 0 };
const TEXT_EXTENSIONS = new Set(["js","ts","jsx","tsx","py","java","rb","go","php","yml","yaml","json","env","properties","xml","html","sh","config","txt","md"]);
const SECRET_NAMES = new Set([".env", "dockerfile", "docker-compose.yml", "docker-compose.yaml"]);
const SKIP_DIRS = /(^|\/)(node_modules|dist|build|\.git|vendor|coverage|\.next|target)(\/|$)/i;
const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|.*\.lock)$/i;
const SKIP_ASSET = /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|mp3|mp4|mov|avi|wav|woff2?|ttf|otf|eot|zip|gz|pdf|exe|dll|so)$/i;

function parseRepo(value) {
  const input = String(value || "").trim().replace(/\/+$/, "");
  if (!input) return null;
  if (/^[^/\\\s]+\/[^/\\\s]+$/.test(input)) {
    const [owner, repo] = input.split("/");
    return owner && repo ? { owner, repo: repo.replace(/\.git$/i, "") } : null;
  }
  try {
    const url = new URL(input);
    if (url.hostname.toLowerCase() !== "github.com") return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 2) return null;
    return { owner: parts[0], repo: parts[1].replace(/\.git$/i, "") };
  } catch (_) { return null; }
}

function headers() {
  const h = { Accept: "application/vnd.github+json" };
  if (state.token) h.Authorization = `Bearer ${state.token}`;
  return h;
}
function updateRate(response) {
  const remaining = response.headers.get("X-RateLimit-Remaining");
  if (remaining !== null) state.rate = { remaining: Number(remaining), limit: Number(response.headers.get("X-RateLimit-Limit") || 60), reset: Number(response.headers.get("X-RateLimit-Reset") || 0) };
}
function rateText() {
  if (!state.rate) return "GitHub API rate limit: checking…";
  const reset = state.rate.reset ? new Date(state.rate.reset * 1000).toLocaleTimeString() : "unknown";
  return `GitHub API: ${state.rate.remaining}/${state.rate.limit} requests remaining · reset ${reset}`;
}
function setStatus(text) { document.getElementById("status").textContent = text; }
function setProgress(percent, label) {
  document.getElementById("progress-wrap").hidden = false;
  document.getElementById("progress").value = percent;
  document.getElementById("progress-count").textContent = `${Math.round(percent)}%`;
  document.getElementById("progress-label").textContent = label;
}
function setBusy(busy) { document.getElementById("scan-button").disabled = busy; }
function isCandidate(path) {
  if (SKIP_DIRS.test(path) || SKIP_FILE.test(path) || SKIP_ASSET.test(path)) return false;
  const name = path.split("/").pop().toLowerCase();
  if (SECRET_NAMES.has(name)) return true;
  const dot = name.lastIndexOf(".");
  return dot > 0 && TEXT_EXTENSIONS.has(name.slice(dot + 1));
}
async function githubFetch(url) {
  let response;
  try { response = await fetch(url, { headers: headers() }); }
  catch (cause) { throw new Error(`Network failure while contacting GitHub: ${cause.message}`); }
  updateRate(response);
  if (!response.ok) {
    if (response.status === 404) throw new Error("Repository not found or is not public.");
    if (response.status === 403 && state.rate && state.rate.remaining === 0) throw new Error(`GitHub API rate limit exceeded. Reset time: ${new Date(state.rate.reset * 1000).toLocaleString()}.`);
    throw new Error(`GitHub API error (${response.status}).`);
  }
  return response.json();
}
async function fetchFileTree() {
  const base = `https://api.github.com/repos/${encodeURIComponent(state.repo.owner)}/${encodeURIComponent(state.repo.repo)}`;
  const meta = await githubFetch(base);
  state.branch = meta.default_branch;
  const tree = await githubFetch(`${base}/git/trees/${encodeURIComponent(state.branch)}?recursive=1`);
  state.files = (tree.tree || []).filter(item => item.type === "blob" && isCandidate(item.path));
  console.debug("SecretSweep candidate files", state.files.map(file => file.path));
  return state.files;
}

const form = document.getElementById("scan-form");
const repoInput = document.getElementById("repo-input");
const tokenInput = document.getElementById("token-input");
const error = document.getElementById("repo-error");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const parsed = parseRepo(repoInput.value);
  if (!parsed) { error.hidden = false; error.textContent = "Enter a valid GitHub repository as owner/repo or a github.com repository URL."; repoInput.focus(); return; }
  error.hidden = true; state.repo = parsed; state.token = tokenInput.value; state.findings = [];
  setBusy(true); document.getElementById("results-section").hidden = true;
  try {
    setProgress(2, "Fetching repository metadata…");
    const files = await fetchFileTree();
    if (!files.length) throw new Error("No scannable text files were found in this repository.");
    setProgress(5, `${files.length} candidate files found · ${rateText()}`);
    setStatus(`Ready to scan ${parsed.owner}/${parsed.repo} on ${state.branch}.`);
  } catch (cause) { setStatus(cause.message); }
  finally { setBusy(false); }
});
window.secretSweep = { state, parseRepo, isCandidate, fetchFileTree };
