export interface CreateScanResponse {
  scanId: string;
}

export interface VulnerabilitySummary {
  totalVulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Vulnerability {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  location: string;
  owaspCategory: string;
}

export interface ScanResult {
  scanId: string;
  status: "pending" | "running" | "completed" | "failed";
  score: number;
  grade: string;
  summary: VulnerabilitySummary;
  vulnerabilities: Vulnerability[];
}

export interface WebhookPayload {
  scanId: string;
  repoOwner: string;
  repoName: string;
  prNumber: number;
  githubToken: string;
  iacFiles: IacFile[];
}

export interface IacFile {
  filename: string;
  content: string;
}

export interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: {
    tags?: string[];
  };
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri: string };
      region?: { startLine?: number };
    };
  }>;
}
