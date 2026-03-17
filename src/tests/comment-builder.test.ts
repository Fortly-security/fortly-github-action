// ---------------------------------------------------------------------------
// ActionCommentBuilder tests
//
// The comment-builder module does not exist yet. These tests define the
// expected contract for building PR comment bodies from scan results.
// ---------------------------------------------------------------------------

interface VulnSummary {
  totalVulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface Vulnerability {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  location: string;
  owaspCategory?: string;
}

interface IacFinding {
  ruleId: string;
  severity: string;
  title: string;
  filename: string;
  lineNumber?: number;
  remediation: string;
}

interface CommentInput {
  score: number;
  grade: string;
  summary: VulnSummary;
  vulnerabilities: Vulnerability[];
  scanId: string;
  reportUrl: string;
  iacFindings?: IacFinding[];
}

// ---------------------------------------------------------------------------
// Reference implementation of the comment builder contract
// ---------------------------------------------------------------------------

function buildComment(input: CommentInput): string {
  let body = `## Fortly Security Scan Results\n\n`;
  body += `**Score: ${input.score}/100 (Grade: ${input.grade})**\n\n`;

  if (input.summary.totalVulnerabilities === 0) {
    body += `### :white_check_mark: No vulnerabilities found\n\n`;
  } else {
    body += `| Severity | Count |\n`;
    body += `|----------|-------|\n`;
    body += `| Critical | ${input.summary.critical} |\n`;
    body += `| High | ${input.summary.high} |\n`;
    body += `| Medium | ${input.summary.medium} |\n`;
    body += `| Low | ${input.summary.low} |\n\n`;

    if (input.vulnerabilities.length > 0) {
      body += `### Vulnerabilities Found\n\n`;
      for (const v of input.vulnerabilities.slice(0, 10)) {
        body += `- **${v.severity}** ${v.title} (${v.location})\n`;
      }
      body += `\n`;
    }
  }

  // IaC section
  if (input.iacFindings && input.iacFindings.length > 0) {
    body += `---\n\n`;
    body += `## Infrastructure as Code Findings\n\n`;
    for (const f of input.iacFindings) {
      body += `- **${f.severity.toUpperCase()}** [${f.ruleId}] ${f.title} (\`${f.filename}\`)\n`;
    }
    body += `\n`;
  }

  // Report link
  body += `[View Full Report](${input.reportUrl})\n\n`;

  // Branding footer
  body += `---\n_Powered by [Fortly](https://fortly.io)_\n`;

  return body;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ActionCommentBuilder", () => {
  it('build comment with 0 vulnerabilities includes "No vulnerabilities found" and checkmark', () => {
    const comment = buildComment({
      score: 100,
      grade: "A",
      summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
      vulnerabilities: [],
      scanId: "scan-001",
      reportUrl: "https://fortly.app/scans/scan-001",
    });

    expect(comment).toContain("No vulnerabilities found");
    expect(comment).toContain(":white_check_mark:");
    expect(comment).toContain("Score: 100/100");
    expect(comment).toContain("Grade: A");
  });

  it("build comment with 3 critical vulns includes severity table with correct counts", () => {
    const comment = buildComment({
      score: 15,
      grade: "F",
      summary: { totalVulnerabilities: 5, critical: 3, high: 1, medium: 1, low: 0 },
      vulnerabilities: [
        { severity: "CRITICAL", title: "RCE in /api", location: "/api/exec", owaspCategory: "A03" },
        { severity: "CRITICAL", title: "SQL Injection", location: "/login" },
        { severity: "CRITICAL", title: "XXE in parser", location: "/upload" },
        { severity: "HIGH", title: "XSS in search", location: "/search" },
        { severity: "MEDIUM", title: "Missing headers", location: "/" },
      ],
      scanId: "scan-002",
      reportUrl: "https://fortly.app/scans/scan-002",
    });

    expect(comment).toContain("| Critical | 3 |");
    expect(comment).toContain("| High | 1 |");
    expect(comment).toContain("| Medium | 1 |");
    expect(comment).toContain("| Low | 0 |");
    expect(comment).toContain("RCE in /api");
    expect(comment).toContain("SQL Injection");
    expect(comment).toContain("XXE in parser");
  });

  it('build comment with IaC findings includes "Infrastructure as Code" section', () => {
    const comment = buildComment({
      score: 60,
      grade: "C",
      summary: { totalVulnerabilities: 1, critical: 0, high: 1, medium: 0, low: 0 },
      vulnerabilities: [
        { severity: "HIGH", title: "SQL Injection", location: "/login" },
      ],
      scanId: "scan-003",
      reportUrl: "https://fortly.app/scans/scan-003",
      iacFindings: [
        {
          ruleId: "TF-S3-PUBLIC-ACL",
          severity: "critical",
          title: "S3 bucket with public ACL",
          filename: "main.tf",
          lineNumber: 5,
          remediation: "Remove public ACL.",
        },
        {
          ruleId: "DOCKER-USER-ROOT",
          severity: "high",
          title: "Container runs as root",
          filename: "Dockerfile",
          lineNumber: 3,
          remediation: "Use non-root user.",
        },
      ],
    });

    expect(comment).toContain("Infrastructure as Code");
    expect(comment).toContain("TF-S3-PUBLIC-ACL");
    expect(comment).toContain("DOCKER-USER-ROOT");
    expect(comment).toContain("main.tf");
    expect(comment).toContain("Dockerfile");
  });

  it("comment includes link to full report", () => {
    const reportUrl = "https://fortly.app/scans/scan-999";

    const comment = buildComment({
      score: 80,
      grade: "B",
      summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
      vulnerabilities: [],
      scanId: "scan-999",
      reportUrl,
    });

    expect(comment).toContain("[View Full Report]");
    expect(comment).toContain(reportUrl);
  });

  it("comment includes Fortly branding footer", () => {
    const comment = buildComment({
      score: 90,
      grade: "A",
      summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
      vulnerabilities: [],
      scanId: "scan-100",
      reportUrl: "https://fortly.app/scans/scan-100",
    });

    expect(comment).toContain("Fortly");
    expect(comment).toContain("Powered by");
    expect(comment).toContain("fortly.io");
  });

  // New priority-based comment tests
  describe("Priority-based comments (CommentBuilder class)", () => {
    // Import the actual class
    const { CommentBuilder } = require("../comment-builder");

    it("separates confirmed from potential findings", () => {
      const result = {
        scanId: "scan-001",
        status: "completed",
        score: 30,
        grade: "F",
        summary: { totalVulnerabilities: 3, critical: 1, high: 1, medium: 1, low: 0 },
        vulnerabilities: [
          { severity: "CRITICAL", title: "SQL Injection", location: "/api/login", owaspCategory: "A03" },
          { severity: "HIGH", title: "XSS", location: "/search", owaspCategory: "A07" },
          { severity: "MEDIUM", title: "Missing Headers", location: "/", owaspCategory: "A05" },
        ],
      };

      const comment = CommentBuilder.build(result, "scan-001", "https://api.fortly.io", 0);
      expect(comment).toContain("confirmed exploitable");
      expect(comment).toContain("Potential Findings");
    });

    it("shows action-required message for confirmed vulns", () => {
      const result = {
        scanId: "scan-002",
        status: "completed",
        score: 20,
        grade: "F",
        summary: { totalVulnerabilities: 1, critical: 1, high: 0, medium: 0, low: 0 },
        vulnerabilities: [
          { severity: "CRITICAL", title: "SQL Injection", location: "/api/users", owaspCategory: "A03" },
        ],
      };

      const comment = CommentBuilder.build(result, "scan-002", "https://api.fortly.io", 0);
      expect(comment).toContain("immediate action");
    });

    it("shows no vulnerabilities message when clean", () => {
      const result = {
        scanId: "scan-003",
        status: "completed",
        score: 100,
        grade: "A+",
        summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
        vulnerabilities: [],
      };

      const comment = CommentBuilder.build(result, "scan-003", "https://api.fortly.io", 0);
      expect(comment).toContain("No vulnerabilities found");
    });

    it("includes report link", () => {
      const result = {
        scanId: "scan-004",
        status: "completed",
        score: 50,
        grade: "D",
        summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
        vulnerabilities: [],
      };

      const comment = CommentBuilder.build(result, "scan-004", "https://api.fortly.io", 0);
      expect(comment).toContain("https://api.fortly.io/scans/scan-004");
    });
  });
});
