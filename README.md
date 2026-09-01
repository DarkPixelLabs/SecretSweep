# SecretSweep

SecretSweep is a browser-only scanner for obvious hardcoded secrets in public GitHub repositories. Paste a repository URL or `owner/repo`, and the app fetches the current default-branch file tree and text-file contents directly from GitHub's public REST API. Detection happens locally in your browser.

## Why this is safe

- Repository content is fetched directly from `api.github.com`.
- There is no backend, relay server, database, account system, or scan-history service.
- The optional GitHub Personal Access Token is held in memory for the session, never logged or stored, and is sent only as an `Authorization` header to GitHub API requests.
- Findings show only redacted previews and the exported Markdown report never contains raw secret values.

## Run locally

Open `index.html` in a modern browser. No package manager or build step is required.

## GitHub Pages

The repository contains a GitHub Actions workflow that deploys the static site to GitHub Pages whenever `main` changes. In repository settings, set Pages to use **GitHub Actions** if it is not already enabled.

## Detection patterns

- AWS Access Key
- Google API Key
- GitHub Token
- OpenAI-style key
- Slack Token
- Generic JWT
- Private key block
- Hardcoded password assignment
- Possible secret (high entropy), using a Shannon-entropy heuristic for 24+ character assigned values while skipping obvious non-secret fields such as UUIDs and explicitly named hashes/checksums

Named-prefix patterns use high confidence, password assignments use medium confidence, and entropy-based findings use low confidence.

## API rate limit

Without authentication, GitHub's REST API allows **60 requests per hour per IP**. SecretSweep reads `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers and warns before a scan would exceed the available request budget. An optional personal access token can raise the authenticated limit to **5,000 requests per hour**. The token is never stored by SecretSweep.

Candidate files over 1 MB are skipped. If the remaining API budget is smaller than the scannable file set, SecretSweep offers a partial scan using the available request budget.

## Limitations

SecretSweep scans only the current default branch. It does **not** inspect Git history or previous commits, and it does not provide an OAuth flow or a server-side scanner. A token may be supplied manually for repositories the token is authorized to read.

A clean report does not guarantee a repository is secret-free. Review configuration, environment files, deployment settings, and Git history manually.

## Browser support

Designed for current Chrome, Firefox, and Safari and responsive down to 375px.

## License

MIT
