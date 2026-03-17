# Fortly Security Scan Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Fortly%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/fortly-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Automated security scanning for your GitHub repositories. Fortly analyzes your application code and infrastructure-as-code (IaC) files on every pull request, providing a security score, vulnerability details, and actionable remediation guidance directly in your PR comments.

---

## Quick Start

### 1. Add your API key as a repository secret

Go to **Settings > Secrets and variables > Actions > New repository secret** and create a secret named `FT_API_KEY` with your Fortly API key.

You can obtain an API key at [https://fortly.io/settings/api-keys](https://fortly.io/settings/api-keys).

### 2. Create the workflow file

Add the following to `.github/workflows/fortly-scan.yml`:

```yaml
name: Fortly Security Scan

on:
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fortly/fortly-action@v1
        with:
          api-key: ${{ secrets.FT_API_KEY }}
          target-url: ${{ vars.STAGING_URL || 'https://staging.example.com' }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 3. Push a pull request

Open or update a PR targeting `main` or `develop`. Fortly will run automatically and post a comment with the scan results.

---

## Inputs

| Input              | Description                                                                 | Required | Default   |
|--------------------|-----------------------------------------------------------------------------|----------|-----------|
| `api-key`          | Fortly API key. Store as a repository secret (`FT_API_KEY`).                | Yes      | -         |
| `target-url`       | URL of the application to scan, or `"iac-only"` for IaC-only scans.        | Yes      | -         |
| `fail-threshold`   | Minimum security score (0-100) required to pass the check.                  | No       | `"70"`    |
| `scan-iac`         | Enable infrastructure-as-code scanning (`"true"` or `"false"`).             | No       | `"false"` |
| `scan-mode`        | Scan depth: `"quick"` for fast feedback or `"full"` for comprehensive scan. | No       | `"quick"` |
| `comment-on-pr`    | Post scan results as a PR comment (`"true"` or `"false"`).                  | No       | `"true"`  |

## Outputs

| Output              | Description                                                        |
|---------------------|--------------------------------------------------------------------|
| `score`             | Numeric security score from 0 to 100.                              |
| `grade`             | Letter grade (`A+`, `A`, `B`, `C`, `D`, `F`).                     |
| `vulnerabilities`   | Total number of vulnerabilities found.                             |
| `critical-count`    | Number of critical-severity vulnerabilities.                       |
| `passed`            | Whether the scan passed the threshold (`"true"` or `"false"`).     |
| `scan-url`          | Direct link to the full scan report on Fortly.                     |

---

## Usage Examples

### Basic scan on pull requests

```yaml
- uses: fortly/fortly-action@v1
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: "https://staging.example.com"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### With IaC scanning enabled

```yaml
- uses: fortly/fortly-action@v1
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: "https://staging.example.com"
    scan-iac: "true"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Full scan on main branch

```yaml
- uses: fortly/fortly-action@v1
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: ${{ vars.PRODUCTION_URL }}
    scan-mode: "full"
    fail-threshold: "60"
    comment-on-pr: "false"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Custom threshold with strict enforcement

```yaml
- uses: fortly/fortly-action@v1
  with:
    api-key: ${{ secrets.FT_API_KEY }}
    target-url: "https://staging.example.com"
    fail-threshold: "90"
    scan-iac: "true"
    scan-mode: "quick"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## PR Comment Example

When `comment-on-pr` is enabled, Fortly posts a summary directly on the pull request:

```
+----------------------------------------------------------+
|  Fortly Security Report                                  |
|  Score: 82/100  |  Grade: B  |  Status: PASSED           |
|----------------------------------------------------------|
|  Vulnerabilities found: 5                                |
|    Critical: 0  |  High: 1  |  Medium: 3  |  Low: 1     |
|----------------------------------------------------------|
|  IaC Issues: 2 warnings                                  |
|  Full report: https://fortly.io/scan/abc123              |
+----------------------------------------------------------+
```

---

## Troubleshooting

### "Invalid API key" error

Verify that `FT_API_KEY` is correctly set in your repository secrets. Make sure there are no leading or trailing whitespace characters. You can regenerate your key at [https://fortly.io/settings/api-keys](https://fortly.io/settings/api-keys).

### Scan times out

Full scans on large applications may exceed the default timeout. Try switching to `scan-mode: "quick"` for PR checks and reserve `"full"` for scheduled or push-based workflows.

### PR comment not appearing

Ensure the workflow has `pull-requests: write` permission and that `GITHUB_TOKEN` is passed as an environment variable. If your repository uses a custom GitHub App token, make sure it has the `pull_requests` scope.

### SARIF upload fails

The SARIF file (`fortly-results.sarif`) is only generated in `"full"` scan mode. Make sure you are using `scan-mode: "full"` and that the workflow has `security-events: write` permission.

### Score lower than expected

Fortly scores are cumulative. Even low-severity findings reduce the score. Review the full report at the URL provided in `scan-url` to see the breakdown and prioritize remediation.

---

## Documentation

For complete documentation, advanced configuration, and API reference, visit [https://docs.fortly.io](https://docs.fortly.io).
