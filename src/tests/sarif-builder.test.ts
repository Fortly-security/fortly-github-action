import { SarifBuilder } from "../sarif-builder";
import { ScanResult } from "../types";

describe("SarifBuilder", () => {
  const baseScanResult: ScanResult = {
    scanId: "scan-001",
    status: "completed",
    score: 45,
    grade: "D",
    summary: { totalVulnerabilities: 3, critical: 1, high: 1, medium: 1, low: 0 },
    vulnerabilities: [
      { severity: "CRITICAL", title: "SQL Injection", location: "/api/login", owaspCategory: "A03:2021" },
      { severity: "HIGH", title: "XSS", location: "/search", owaspCategory: "A07:2017" },
      { severity: "MEDIUM", title: "Missing Headers", location: "/", owaspCategory: "A05:2021" },
    ],
  };

  it("generates valid SARIF 2.1.0 schema", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
  });

  it("includes Fortly as tool driver", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("Fortly");
    expect(driver.informationUri).toBe("https://fortly.io");
  });

  it("maps all vulnerabilities to SARIF results", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    expect(sarif.runs[0].results).toHaveLength(3);
  });

  it("maps CRITICAL severity to error level", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const criticalResult = sarif.runs[0].results.find(r => r.ruleId === "sql-injection");
    expect(criticalResult?.level).toBe("error");
  });

  it("maps HIGH severity to error level", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const highResult = sarif.runs[0].results.find(r => r.ruleId === "xss");
    expect(highResult?.level).toBe("error");
  });

  it("maps MEDIUM severity to warning level", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const medResult = sarif.runs[0].results.find(r => r.ruleId === "missing-headers");
    expect(medResult?.level).toBe("warning");
  });

  it("creates unique rules from vulnerabilities", () => {
    const resultWithDupes: ScanResult = {
      ...baseScanResult,
      vulnerabilities: [
        { severity: "CRITICAL", title: "SQL Injection", location: "/api/login", owaspCategory: "A03:2021" },
        { severity: "HIGH", title: "SQL Injection", location: "/api/users", owaspCategory: "A03:2021" },
        { severity: "MEDIUM", title: "XSS", location: "/search", owaspCategory: "A07:2017" },
      ],
    };
    const sarif = SarifBuilder.build(resultWithDupes, "scan-002", "https://api.fortly.io");
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2); // sql-injection and xss
    expect(sarif.runs[0].results).toHaveLength(3); // all 3 results
  });

  it("includes location URI from vulnerability", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const result = sarif.runs[0].results[0];
    expect(result.locations?.[0]?.physicalLocation?.artifactLocation?.uri).toBe("/api/login");
  });

  it("includes OWASP category in rule tags", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const sqlRule = sarif.runs[0].tool.driver.rules.find(r => r.id === "sql-injection");
    expect(sqlRule?.properties?.tags).toContain("A03:2021");
  });

  it("handles empty vulnerabilities array", () => {
    const emptyResult: ScanResult = {
      ...baseScanResult,
      summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0 },
      vulnerabilities: [],
    };
    const sarif = SarifBuilder.build(emptyResult, "scan-003", "https://api.fortly.io");
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it("includes helpUri pointing to Fortly docs", () => {
    const sarif = SarifBuilder.build(baseScanResult, "scan-001", "https://api.fortly.io");
    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.helpUri).toContain("https://api.fortly.io/docs/vulnerabilities/");
  });
});
