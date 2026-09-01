"use strict";

// Privacy boundary: repository content is fetched directly from api.github.com and scanned in this browser.
// The app never sends repository content to a relay server, never logs the optional token, and never stores it.

const state = { repo: null, token: "", branch: "", files: [], findings: [], rate: null };

function parseRepo(value) {
  const input = String(value || "").trim().replace(/\/+$/, "");
  if (!input) return null;
  if (/^[^/\\\s]+\/[^/\\\s]+$/.test(input)) {
    const [owner, repo] = input.split("/");
    return { owner, repo: repo.replace(/\.git$/i, "") };
  }
  try {
    const url = new URL(input);
    if (url.hostname.toLowerCase() !== "github.com") return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 2) return null;
    return { owner: parts[0], repo: parts[1].replace(/\.git$/i, "") };
  } catch (_) {
    return null;
  }
}

const form = document.getElementById("scan-form");
const repoInput = document.getElementById("repo-input");
const tokenInput = document.getElementById("token-input");
const error = document.getElementById("repo-error");
const status = document.getElementById("status");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const parsed = parseRepo(repoInput.value);
  if (!parsed) {
    error.hidden = false;
    error.textContent = "Enter a valid GitHub repository as owner/repo or a github.com repository URL.";
    repoInput.focus();
    return;
  }
  error.hidden = true;
  state.repo = parsed;
  state.token = tokenInput.value;
  status.textContent = `Ready to scan ${parsed.owner}/${parsed.repo}.`;
});

window.secretSweep = { state, parseRepo };
