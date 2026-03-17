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
