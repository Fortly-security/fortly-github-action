# fortly-github-action

GitHub Action for automated security scanning in CI/CD pipelines.

Fortly scans your web applications and infrastructure-as-code files on every pull request, providing a security score, vulnerability breakdown, and remediation guidance. Results are posted as PR comments and can be uploaded to the GitHub Security tab via SARIF.

---

## Usage

Add the following workflow to `.github/workflows/fortly-scan.yml`:

```yaml
name: Fortly Security Scan

on:
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: fortly/fortly-github-action@v1
        id: fortly
        with:
          api-key: ${{ secrets.FT_API_KEY }}
          target-url: "https://staging.example.com"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Check results
        run: |
          echo "Score: ${{ steps.fortly.outputs.score }}"
          echo "Grade: ${{ steps.fortly.outputs.grade }}"
          echo "Vulnerabilities: ${{ steps.fortly.outputs.vulnerabilities }}"
          echo "Passed: ${{ steps.fortly.outputs.passed }}"
```

---

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `api-key` | Fortly API key. Store as a repository secret (`FT_API_KEY`). Get one at [fortly.io/settings/api-keys](https://fortly.io/settings/api-keys). | Yes | -- |
| `target-url` | URL of the application to scan. Set to `"iac-only"` for infrastructure-only scans. | Yes | -- |
| `fail-threshold` | Minimum security score (0-100) required to pass the check. The action fails if the score is below this value. | No | `60` |
| `scan-iac` | Enable IaC scanning for Terraform, Docker, and Kubernetes files changed in the PR. | No | `true` |
| `scan-mode` | Scan depth: `quick` (approximately 30 seconds, top vulnerabilities) or `full` (approximately 5 minutes, all modules). | No | `quick` |
| `comment-on-pr` | Post scan results as a comment on the pull request. | No | `true` |
| `api-url` | Fortly API base URL. Override for self-hosted instances. | No | `https://api.fortly.io` |

---

## Outputs

| Output | Description |
|---|---|
| `score` | Numeric security score from 0 to 100. |
| `grade` | Letter grade: `A+`, `A`, `B`, `C`, `D`, or `F`. |
| `vulnerabilities` | Total number of vulnerabilities found. |
| `critical-count` | Number of critical-severity vulnerabilities. |
| `high-count` | Number of high-severity vulnerabilities. |
| `scan-url` | Direct link to the full scan report on Fortly. |
| `passed` | Whether the scan passed the threshold (`true` or `false`). |

---

## Features

### Automatic PR Scanning

Fortly runs automatically on every pull request. No manual triggers needed. Configure the branches to scan in the workflow `on` trigger.

### PR Comments

When `comment-on-pr` is enabled (default), Fortly posts a detailed summary on the pull request including the security score, grade, vulnerability counts by severity, IaC findings, and a link to the full report.

### IaC Scanning

When `scan-iac` is enabled (default), Fortly analyzes infrastructure-as-code files changed in the PR:

- **Terraform** -- Misconfigured resources, overly permissive IAM policies, unencrypted storage
- **Dockerfile** -- Running as root, insecure base images, exposed secrets
- **Kubernetes** -- Privileged containers, missing resource limits, insecure network policies

### SARIF Upload

Fortly generates SARIF 2.1.0 output that can be uploaded to the GitHub Security tab:

```yaml
- uses: fortly/fortly-github-action@v1
  id: fortly
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: "https://staging.example.com"
    scan-mode: "full"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: fortly-results.sarif
```

Vulnerabilities appear in the **Security** tab of your repository alongside CodeQL and other scanning tools.

### Status Checks

The action sets a pass/fail status based on the `fail-threshold` input. Pull requests that do not meet the minimum score will have a failed check, blocking merge when branch protection rules are configured.

---

## Workflow Examples

### Basic PR Scan

```yaml
name: Fortly Security Scan

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fortly/fortly-github-action@v1
        with:
          api-key: ${{ secrets.FT_API_KEY }}
          target-url: ${{ vars.STAGING_URL }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Full Scan with IaC and SARIF

```yaml
name: Fortly Full Scan

on:
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: fortly/fortly-github-action@v1
        id: fortly
        with:
          api-key: ${{ secrets.FT_API_KEY }}
          target-url: "https://staging.example.com"
          scan-mode: "full"
          scan-iac: "true"
          fail-threshold: "80"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: fortly-results.sarif

      - name: Fail if critical vulnerabilities found
        if: steps.fortly.outputs.critical-count != '0'
        run: |
          echo "Critical vulnerabilities detected: ${{ steps.fortly.outputs.critical-count }}"
          exit 1
```

### IaC-Only Scan (No Target URL)

```yaml
- uses: fortly/fortly-github-action@v1
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: "iac-only"
    scan-iac: "true"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Scheduled Full Scan

```yaml
name: Weekly Security Scan

on:
  schedule:
    - cron: "0 6 * * 1"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fortly/fortly-github-action@v1
        with:
          api-key: ${{ secrets.FT_API_KEY }}
          target-url: "https://production.example.com"
          scan-mode: "full"
          comment-on-pr: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## PR Comment Format

When `comment-on-pr` is enabled, Fortly posts a structured summary on the pull request:

```
Fortly Security Report
Score: 82/100 | Grade: B | Status: PASSED

Vulnerabilities found: 5
  Critical: 0 | High: 1 | Medium: 3 | Low: 1

IaC Issues: 2 warnings
Full report: https://fortly.io/scan/abc123
```

The comment is updated on subsequent pushes to the same PR rather than creating duplicate comments.

---

## Project Structure

```
src/
  index.ts              Action entry point
  client.ts             Fortly API client
  comment-builder.ts    PR comment formatting
  iac-collector.ts      IaC file detection and collection
  status-check.ts       GitHub check run management
  types.ts              TypeScript type definitions
  tests/                Unit tests
dist/
  index.js              Compiled bundle (generated by ncc)
action.yml              Action metadata and input/output definitions
```

---

## Stack

| Technology | Purpose |
|---|---|
| TypeScript | Type-safe action implementation |
| Node.js 22 | Runtime |
| @actions/core | GitHub Actions toolkit for inputs, outputs, and logging |
| @actions/github | GitHub API client for PR comments and check runs |
| @vercel/ncc | Bundle compiler for single-file distribution |
| Axios | HTTP client for the Fortly API |
| Jest | Unit testing |

---

## Scripts

```bash
# Build the action (compile and bundle with ncc)
npm run build

# Run tests with coverage
npm run test

# Type-check without emitting
npm run lint
```

---

## Troubleshooting

**"Invalid API key" error** -- Verify that `FT_API_KEY` is set correctly in repository secrets with no leading or trailing whitespace.

**PR comment not appearing** -- Ensure the workflow has `pull-requests: write` permission and that `GITHUB_TOKEN` is passed as an environment variable.

**Scan timeout** -- Large applications may exceed the default timeout in `quick` mode. Switch to `full` mode or split scanning into separate DAST and IaC jobs.

**SARIF upload fails** -- SARIF files are generated in `full` scan mode. Ensure `scan-mode: "full"` and that the workflow has `security-events: write` permission.

---

## License

[MIT](./LICENSE)
