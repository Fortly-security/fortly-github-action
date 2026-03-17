import { ScanResult } from "./types";

export class CommentBuilder {
  static build(
    result: ScanResult,
    scanId: string,
    apiUrl: string,
    iacFileCount: number
  ): string {
    const lines: string[] = [];

    // Header
    const statusEmoji = result.score >= 80 ? "✅" : result.score >= 50 ? "⚠️" : "🚨";
    lines.push(`## 🛡️ Fortly Security Scan`);
    lines.push("");
    lines.push(
      `**Score: ${result.score}/100 (Grade: ${result.grade})** | ${statusEmoji} ${result.summary.totalVulnerabilities} vulnerabilities found`
    );
    lines.push("");

    // Severity table
    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    lines.push(`| 🟠 High | ${result.summary.high} |`);
    lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
    lines.push(`| 🟢 Low | ${result.summary.low} |`);
    lines.push("");

    // Top findings
    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
      lines.push("### Top Findings");

      const topFindings = result.vulnerabilities.slice(0, 10);
      for (const vuln of topFindings) {
        const icon = this.severityIcon(vuln.severity);
        lines.push(
          `- ${icon} **${vuln.severity}** ${vuln.title} in ${vuln.location} (${vuln.owaspCategory})`
        );
      }
      lines.push("");
    }

    // IaC section
    if (iacFileCount > 0) {
      lines.push("### Infrastructure as Code");
      lines.push(
        `📁 ${iacFileCount} IaC files scanned`
      );
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
      case "CRITICAL":
        return "🔴";
      case "HIGH":
        return "🟠";
      case "MEDIUM":
        return "🟡";
      case "LOW":
        return "🟢";
      default:
        return "⚪";
    }
  }
}
