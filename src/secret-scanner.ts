import * as core from "@actions/core";

export interface SecretFinding {
  type: string;
  provider: string;
  severity: "critical" | "high" | "medium";
  filename: string;
  lineNumber: number;
  snippet: string;
  description: string;
}

interface SecretPattern {
  id: string;
  provider: string;
  severity: "critical" | "high" | "medium";
  pattern: RegExp;
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  { id: "aws-access-key-id", provider: "AWS", severity: "critical", pattern: /AKIA[0-9A-Z]{16}/g, description: "AWS Access Key ID" },
  { id: "aws-secret-key", provider: "AWS", severity: "critical", pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, description: "AWS Secret Access Key" },
  // GitHub
  { id: "github-pat", provider: "GitHub", severity: "critical", pattern: /ghp_[A-Za-z0-9]{36}/g, description: "GitHub Personal Access Token" },
  { id: "github-oauth", provider: "GitHub", severity: "critical", pattern: /gho_[A-Za-z0-9]{36}/g, description: "GitHub OAuth Token" },
  { id: "github-app-token", provider: "GitHub", severity: "critical", pattern: /(?:ghu|ghs)_[A-Za-z0-9]{36}/g, description: "GitHub App Token" },
  { id: "github-fine-grained", provider: "GitHub", severity: "critical", pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g, description: "GitHub Fine-Grained PAT" },
  // GCP
  { id: "gcp-api-key", provider: "GCP", severity: "critical", pattern: /AIza[0-9A-Za-z_-]{35}/g, description: "Google Cloud API Key" },
  // Stripe
  { id: "stripe-secret", provider: "Stripe", severity: "critical", pattern: /sk_live_[A-Za-z0-9]{24,}/g, description: "Stripe Secret Key" },
  { id: "stripe-restricted", provider: "Stripe", severity: "critical", pattern: /rk_live_[A-Za-z0-9]{24,}/g, description: "Stripe Restricted Key" },
  // Slack
  { id: "slack-bot-token", provider: "Slack", severity: "high", pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}/g, description: "Slack Bot Token" },
  { id: "slack-webhook", provider: "Slack", severity: "high", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, description: "Slack Webhook URL" },
  // Database
  { id: "postgres-uri", provider: "Database", severity: "critical", pattern: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\s/]+/g, description: "PostgreSQL Connection URI" },
  { id: "mysql-uri", provider: "Database", severity: "critical", pattern: /mysql:\/\/[^:\s]+:[^@\s]+@[^\s/]+/g, description: "MySQL Connection URI" },
  { id: "mongodb-uri", provider: "Database", severity: "critical", pattern: /mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s/]+/g, description: "MongoDB Connection URI" },
  { id: "redis-uri", provider: "Database", severity: "critical", pattern: /redis:\/\/[^:\s]+:[^@\s]+@[^\s/]+/g, description: "Redis Connection URI" },
  // Private Keys
  { id: "rsa-private-key", provider: "Crypto", severity: "critical", pattern: /-----BEGIN RSA PRIVATE KEY-----/g, description: "RSA Private Key" },
  { id: "ec-private-key", provider: "Crypto", severity: "critical", pattern: /-----BEGIN EC PRIVATE KEY-----/g, description: "EC Private Key" },
  { id: "openssh-private-key", provider: "Crypto", severity: "critical", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, description: "OpenSSH Private Key" },
  // NPM / PyPI / Docker
  { id: "npm-token", provider: "npm", severity: "high", pattern: /npm_[A-Za-z0-9]{36}/g, description: "npm Access Token" },
  { id: "pypi-token", provider: "PyPI", severity: "high", pattern: /pypi-[A-Za-z0-9]{60,}/g, description: "PyPI API Token" },
  { id: "docker-hub-token", provider: "Docker", severity: "high", pattern: /dckr_pat_[A-Za-z0-9_-]+/g, description: "Docker Hub PAT" },
  // Twilio / SendGrid
  { id: "twilio-api-key", provider: "Twilio", severity: "high", pattern: /SK[a-f0-9]{32}/g, description: "Twilio API Key" },
  { id: "sendgrid-api-key", provider: "SendGrid", severity: "high", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, description: "SendGrid API Key" },
  // Azure
  { id: "azure-storage-key", provider: "Azure", severity: "critical", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88}/g, description: "Azure Storage Connection String" },
  // JWT
  { id: "jwt-token", provider: "Auth", severity: "high", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, description: "JSON Web Token" },
  // Generic
  { id: "generic-password", provider: "Generic", severity: "medium", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]/gi, description: "Hardcoded Password" },
  { id: "generic-api-key", provider: "Generic", severity: "medium", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]/gi, description: "Hardcoded API Key" },
  { id: "generic-secret", provider: "Generic", severity: "medium", pattern: /(?:secret|client_secret)\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]/gi, description: "Hardcoded Secret" },
];

const ALLOWLIST: RegExp[] = [
  /REPLACE_ME|your[_-]?api[_-]?key|YOUR[_-]?API[_-]?KEY|<your[_-]?key>/i,
  /example\.com|localhost|127\.0\.0\.1/,
  /xxxx|XXXX|\*{4,}|placeholder/i,
  /test[_-]?key|fake[_-]?key|dummy|sample/i,
  /\.test\.(ts|js|py|go|java)$/,  // test files
  /\.example$|\.sample$/,
  /node_modules\//,
];

function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return value.substring(0, 4) + "****" + value.substring(value.length - 4);
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split("\n").length;
}

function getSnippetAtLine(content: string, lineNum: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNum - 2);
  const end = Math.min(lines.length, lineNum + 1);
  return lines.slice(start, end).map((line, i) => {
    // Mask any secrets in the snippet display
    return `${start + i + 1}: ${line}`;
  }).join("\n");
}

export class SecretScanner {
  static scan(files: { filename: string; content: string }[]): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const seen = new Set<string>();

    for (const file of files) {
      // Skip allowlisted files
      if (ALLOWLIST.some(p => p.test(file.filename))) continue;

      for (const pattern of SECRET_PATTERNS) {
        // Reset regex lastIndex
        pattern.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = pattern.pattern.exec(file.content)) !== null) {
          const matchedText = match[0];

          // Skip allowlisted values
          if (ALLOWLIST.some(p => p.test(matchedText))) continue;

          const lineNumber = getLineNumber(file.content, match.index);
          const dedupeKey = `${pattern.id}:${file.filename}:${lineNumber}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);

          findings.push({
            type: pattern.id,
            provider: pattern.provider,
            severity: pattern.severity,
            filename: file.filename,
            lineNumber,
            snippet: maskSecret(matchedText),
            description: pattern.description,
          });
        }
      }
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return findings;
  }

  static buildPrComment(findings: SecretFinding[]): string {
    if (findings.length === 0) return "";

    const lines: string[] = [];
    lines.push("## 🔐 Fortly Secret Detection\n");
    lines.push(`**${findings.length} secret(s) detected in this PR**\n`);

    const critical = findings.filter(f => f.severity === "critical").length;
    const high = findings.filter(f => f.severity === "high").length;
    const medium = findings.filter(f => f.severity === "medium").length;

    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    if (critical > 0) lines.push(`| 🔴 Critical | ${critical} |`);
    if (high > 0) lines.push(`| 🟠 High | ${high} |`);
    if (medium > 0) lines.push(`| 🟡 Medium | ${medium} |`);
    lines.push("");

    lines.push("### Findings\n");
    for (const f of findings.slice(0, 20)) {
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : "🟡";
      lines.push(`- ${icon} **${f.description}** (\`${f.provider}\`) in \`${f.filename}:${f.lineNumber}\``);
      lines.push(`  - Matched: \`${f.snippet}\``);
    }
    if (findings.length > 20) {
      lines.push(`\n_...and ${findings.length - 20} more findings_`);
    }

    lines.push("\n> ⚠️ **Action Required**: Remove these secrets and rotate the credentials immediately.");
    lines.push("> Consider using environment variables or a secrets manager instead.\n");
    lines.push("---");
    lines.push("*🔐 Scanned by [Fortly](https://fortly.io) — Secret Detection*");

    return lines.join("\n");
  }
}
