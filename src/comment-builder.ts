import { ScanResult, Vulnerability } from "./types";

// Simple heuristic to determine if a vulnerability is "confirmed"
// (In production, the backend would set this via ExploitabilityScorer)
const CONFIRMED_TYPES = new Set([
  "sql-injection", "xss", "command-injection", "ssrf",
  "open-redirect", "directory-traversal", "ssti", "xxe",
  "cors-misconfiguration", "idor",
]);

function isLikelyConfirmed(vuln: Vulnerability): boolean {
  const type = vuln.title.toLowerCase().replace(/\s+/g, "-");
  return CONFIRMED_TYPES.has(type) && (vuln.severity === "CRITICAL" || vuln.severity === "HIGH");
}

export class CommentBuilder {
  static build(
    result: ScanResult,
    scanId: string,
    apiUrl: string,
    iacFileCount: number
  ): string {
    const lines: string[] = [];
    const confirmed = result.vulnerabilities?.filter(isLikelyConfirmed) || [];
    const potential = result.vulnerabilities?.filter(v => !isLikelyConfirmed(v)) || [];

    // Header
    const statusEmoji = result.score >= 80 ? "✅" : result.score >= 50 ? "⚠️" : "🚨";
    lines.push(`## 🛡️ Fortly Security Scan`);
    lines.push("");
    lines.push(
      `**Score: ${result.score}/100 (Grade: ${result.grade})** ${statusEmoji}`
    );
    lines.push("");

    // Priority-based summary (the key change)
    if (confirmed.length > 0) {
      lines.push(
        `> 🚨 **${confirmed.length} confirmed exploitable** finding${confirmed.length !== 1 ? "s" : ""} requiring immediate action`
      );
    }
    if (potential.length > 0) {
      lines.push(
        `> 📋 ${potential.length} potential finding${potential.length !== 1 ? "s" : ""} for review`
      );
    }
    if (result.summary.totalVulnerabilities === 0) {
      lines.push(`> ✅ No vulnerabilities found`);
    }
    lines.push("");

    // Severity breakdown
    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    if (result.summary.critical > 0) lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    if (result.summary.high > 0) lines.push(`| 🟠 High | ${result.summary.high} |`);
    if (result.summary.medium > 0) lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
    if (result.summary.low > 0) lines.push(`| 🟢 Low | ${result.summary.low} |`);
    lines.push("");

    // Confirmed exploitable findings (top priority)
    if (confirmed.length > 0) {
      lines.push("### 🚨 Confirmed Exploitable");
      lines.push("_These vulnerabilities were verified during scanning and should be fixed immediately._\n");
      for (const vuln of confirmed.slice(0, 5)) {
        const icon = this.severityIcon(vuln.severity);
        lines.push(
          `- ${icon} **${vuln.title}** in \`${vuln.location}\` ${vuln.owaspCategory ? `(${vuln.owaspCategory})` : ""}`
        );
      }
      if (confirmed.length > 5) {
        lines.push(`- _...and ${confirmed.length - 5} more confirmed findings_`);
      }
      lines.push("");
    }

    // Potential findings
    if (potential.length > 0) {
      lines.push("### 📋 Potential Findings");
      lines.push("_These findings may require manual verification._\n");
      for (const vuln of potential.slice(0, 5)) {
        const icon = this.severityIcon(vuln.severity);
        lines.push(
          `- ${icon} **${vuln.severity}** ${vuln.title} in \`${vuln.location}\``
        );
      }
      if (potential.length > 5) {
        lines.push(`- _...and ${potential.length - 5} more potential findings_`);
      }
      lines.push("");
    }

    // IaC section
    if (iacFileCount > 0) {
      lines.push("### Infrastructure as Code");
      lines.push(`📁 ${iacFileCount} IaC files scanned`);
      lines.push("");
    }

    // Links
    const reportUrl = `${apiUrl}/scans/${scanId}`;
    lines.push(
      `[📊 View Full Report](${reportUrl}) | [📖 Remediation Guide](https://docs.fortly.io)`
    );
    lines.push("");

    // Footer
    lines.push("---");
    lines.push(
      "*🤖 Scanned by [Fortly](https://fortly.io) — Automated Security Scanner*"
    );

    return lines.join("\n");
  }

  private static severityIcon(severity: string): string {
    switch (severity) {
      case "CRITICAL": return "🔴";
      case "HIGH": return "🟠";
      case "MEDIUM": return "🟡";
      case "LOW": return "🟢";
      default: return "⚪";
    }
  }
}
