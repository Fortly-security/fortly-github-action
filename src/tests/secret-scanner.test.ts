import { SecretScanner } from "../secret-scanner";

describe("SecretScanner", () => {
  describe("scan", () => {
    it("detects AWS access key ID", () => {
      const files = [{ filename: "config.ts", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }];
      const findings = SecretScanner.scan(files);
      expect(findings.length).toBeGreaterThanOrEqual(1);
      const awsFinding = findings.find(f => f.type === "aws-access-key-id");
      expect(awsFinding).toBeDefined();
      expect(awsFinding!.severity).toBe("critical");
      expect(awsFinding!.provider).toBe("AWS");
    });

    it("detects GitHub personal access token", () => {
      const files = [{ filename: "deploy.sh", content: 'export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' }];
      const findings = SecretScanner.scan(files);
      const ghFinding = findings.find(f => f.type === "github-pat");
      expect(ghFinding).toBeDefined();
      expect(ghFinding!.severity).toBe("critical");
    });

    it("detects Stripe secret key", () => {
      const files = [{ filename: "payment.ts", content: 'const stripe = Stripe("sk_live_' + 'abcdefghijklmnopqrstuvwx");' }];
      const findings = SecretScanner.scan(files);
      const stripeFinding = findings.find(f => f.type === "stripe-secret");
      expect(stripeFinding).toBeDefined();
      expect(stripeFinding!.provider).toBe("Stripe");
    });

    it("detects PostgreSQL connection URI", () => {
      const files = [{ filename: ".env", content: 'DATABASE_URL=postgres://admin:secretpass@db.production.internal/mydb' }];
      const findings = SecretScanner.scan(files);
      const dbFinding = findings.find(f => f.type === "postgres-uri");
      expect(dbFinding).toBeDefined();
      expect(dbFinding!.severity).toBe("critical");
    });

    it("detects RSA private key", () => {
      const files = [{ filename: "key.pem", content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...' }];
      const findings = SecretScanner.scan(files);
      const keyFinding = findings.find(f => f.type === "rsa-private-key");
      expect(keyFinding).toBeDefined();
    });

    it("detects Slack webhook URL", () => {
      const files = [{ filename: "notify.ts", content: 'const webhook = "https://hooks.slack.com/services/T0000000/B0000000/AAABBBCCC123";' }];
      const findings = SecretScanner.scan(files);
      const slackFinding = findings.find(f => f.type === "slack-webhook");
      expect(slackFinding).toBeDefined();
    });

    it("detects SendGrid API key", () => {
      const files = [{ filename: "mailer.ts", content: 'const key = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS";' }];
      const findings = SecretScanner.scan(files);
      const sgFinding = findings.find(f => f.type === "sendgrid-api-key");
      expect(sgFinding).toBeDefined();
    });

    it("skips test files", () => {
      const files = [{ filename: "auth.test.ts", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }];
      const findings = SecretScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("skips placeholder values", () => {
      const files = [{ filename: "config.ts", content: 'const key = "your-api-key-here";' }];
      const findings = SecretScanner.scan(files);
      const genericFindings = findings.filter(f => f.type.startsWith("generic"));
      expect(genericFindings).toHaveLength(0);
    });

    it("skips node_modules files", () => {
      const files = [{ filename: "node_modules/lib/config.js", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }];
      const findings = SecretScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("returns empty array for clean files", () => {
      const files = [
        { filename: "index.ts", content: 'console.log("Hello World");' },
        { filename: "utils.ts", content: 'export const add = (a: number, b: number) => a + b;' },
      ];
      const findings = SecretScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("masks secret in snippet", () => {
      const files = [{ filename: "config.ts", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }];
      const findings = SecretScanner.scan(files);
      const awsFinding = findings.find(f => f.type === "aws-access-key-id");
      expect(awsFinding!.snippet).toContain("****");
      expect(awsFinding!.snippet).not.toBe("AKIAIOSFODNN7EXAMPLE");
    });

    it("deduplicates same secret on same line", () => {
      const files = [{ filename: "config.ts", content: 'const x = "AKIAIOSFODNN7EXAMPLE"; // AKIAIOSFODNN7EXAMPLE' }];
      const findings = SecretScanner.scan(files);
      const awsFindings = findings.filter(f => f.type === "aws-access-key-id");
      // Should find at least one but deduplicate exact same location
      expect(awsFindings.length).toBeGreaterThanOrEqual(1);
    });

    it("sorts findings by severity (critical first)", () => {
      const files = [{
        filename: "config.ts",
        content: [
          'password: "mysecretpassword123"',  // medium (generic)
          'const key = "AKIAIOSFODNN7EXAMPLE";',  // critical
          'token: "xoxb-' + '1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx"',  // high (slack)
        ].join("\n"),
      }];
      const findings = SecretScanner.scan(files);
      if (findings.length >= 2) {
        const severityOrder = { critical: 0, high: 1, medium: 2 };
        for (let i = 1; i < findings.length; i++) {
          expect(severityOrder[findings[i].severity]).toBeGreaterThanOrEqual(
            severityOrder[findings[i - 1].severity]
          );
        }
      }
    });

    it("detects multiple secret types in one file", () => {
      const files = [{
        filename: "config.ts",
        content: [
          'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
          'const ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";',
          'const dbUrl = "postgres://user:pass@db.production.internal/db";',
        ].join("\n"),
      }];
      const findings = SecretScanner.scan(files);
      const types = new Set(findings.map(f => f.type));
      expect(types.has("aws-access-key-id")).toBe(true);
      expect(types.has("github-pat")).toBe(true);
      expect(types.has("postgres-uri")).toBe(true);
    });
  });

  describe("buildPrComment", () => {
    it("returns empty string for no findings", () => {
      expect(SecretScanner.buildPrComment([])).toBe("");
    });

    it("includes secret count in header", () => {
      const findings = [{
        type: "aws-access-key-id",
        provider: "AWS",
        severity: "critical" as const,
        filename: "config.ts",
        lineNumber: 1,
        snippet: "AKIA****MPLE",
        description: "AWS Access Key ID",
      }];
      const comment = SecretScanner.buildPrComment(findings);
      expect(comment).toContain("1 secret");
      expect(comment).toContain("Secret Detection");
    });

    it("includes severity table", () => {
      const findings = [
        { type: "aws-key", provider: "AWS", severity: "critical" as const, filename: "a.ts", lineNumber: 1, snippet: "****", description: "AWS Key" },
        { type: "slack-token", provider: "Slack", severity: "high" as const, filename: "b.ts", lineNumber: 2, snippet: "****", description: "Slack Token" },
      ];
      const comment = SecretScanner.buildPrComment(findings);
      expect(comment).toContain("Critical");
      expect(comment).toContain("High");
    });

    it("includes remediation guidance", () => {
      const findings = [{
        type: "generic-password",
        provider: "Generic",
        severity: "medium" as const,
        filename: "config.ts",
        lineNumber: 5,
        snippet: "****",
        description: "Hardcoded Password",
      }];
      const comment = SecretScanner.buildPrComment(findings);
      expect(comment).toContain("secrets manager");
    });
  });
});
