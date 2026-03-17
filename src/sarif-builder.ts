import type {
  ScanResult,
  Vulnerability,
  SarifReport,
  SarifRule,
  SarifResult,
} from "./types";

// ---------------------------------------------------------------------------
// Severity -> SARIF level mapping
// ---------------------------------------------------------------------------

type SeverityLevel = Vulnerability["severity"];

const SEVERITY_TO_LEVEL: Record<SeverityLevel, SarifResult["level"]> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toKebabCase(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// ---------------------------------------------------------------------------
// SarifBuilder
// ---------------------------------------------------------------------------

export class SarifBuilder {
  /**
   * Converts a Fortly ScanResult into a SARIF 2.1.0 report object.
   *
   * @param result  - The scan result containing vulnerabilities.
   * @param scanId  - Unique identifier for this scan run.
   * @param apiUrl  - Base URL of the Fortly API (used for helpUri links).
   * @returns A fully-formed SarifReport ready for serialisation.
   */
  static build(result: ScanResult, scanId: string, apiUrl: string): SarifReport {
    const rulesMap = new Map<string, SarifRule>();
    const results: SarifResult[] = [];

    for (const vuln of result.vulnerabilities) {
      const ruleId = toKebabCase(vuln.title);

      // Deduplicate rules by ruleId
      if (!rulesMap.has(ruleId)) {
        const rule: SarifRule = {
          id: ruleId,
          name: vuln.title,
          shortDescription: { text: vuln.title },
          helpUri: `${apiUrl}/docs/vulnerabilities/${ruleId}`,
        };

        if (vuln.owaspCategory) {
          rule.properties = { tags: [vuln.owaspCategory] };
        }

        rulesMap.set(ruleId, rule);
      }

      results.push({
        ruleId,
        level: SEVERITY_TO_LEVEL[vuln.severity],
        message: { text: `${vuln.title} found at ${vuln.location}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: vuln.location },
            },
          },
        ],
      });
    }

    return {
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Fortly",
              version: "1.0.0",
              informationUri: "https://fortly.io",
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
        },
      ],
    };
  }
}
