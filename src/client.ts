import axios, { AxiosInstance, AxiosError } from "axios";
import * as core from "@actions/core";
import { CreateScanResponse, SarifReport, ScanResult, WebhookPayload } from "./types";

export class FortlyClient {
  private http: AxiosInstance;
  private baseUrl: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl;
    this.http = axios.create({
      baseURL: baseUrl,
      timeout: 30_000,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": "fortly-github-action/1.0.0",
      },
    });

    this.http.interceptors.response.use(undefined, async (error: AxiosError) => {
      if (error.response?.status === 429) {
        const retryAfter = parseInt(
          (error.response.headers["retry-after"] as string) || "5",
          10
        );
        core.warning(`Rate limited by Fortly API. Retrying in ${retryAfter}s...`);
        await this.sleep(retryAfter * 1000);
        return this.http.request(error.config!);
      }
      return Promise.reject(error);
    });
  }

  async createScan(
    targetUrl: string,
    mode: string
  ): Promise<CreateScanResponse> {
    try {
      const response = await this.http.post<CreateScanResponse>(
        "/api/v2/scans",
        {
          targetUrl,
          mode,
        }
      );
      return response.data;
    } catch (error) {
      throw this.wrapError("Failed to create scan", error);
    }
  }

  async getScan(scanId: string): Promise<ScanResult> {
    try {
      const response = await this.http.get<ScanResult>(
        `/api/v2/scans/${scanId}`
      );
      return response.data;
    } catch (error) {
      throw this.wrapError("Failed to get scan status", error);
    }
  }

  async waitForCompletion(
    scanId: string,
    timeoutSeconds: number
  ): Promise<ScanResult> {
    const pollInterval = 5_000;
    const deadline = Date.now() + timeoutSeconds * 1000;

    while (Date.now() < deadline) {
      const result = await this.getScan(scanId);

      if (result.status === "completed") {
        return result;
      }

      if (result.status === "failed") {
        throw new Error(
          `Scan ${scanId} failed. Check https://app.fortly.io/scans/${scanId} for details.`
        );
      }

      core.info(`Scan status: ${result.status}. Polling again in 5s...`);
      await this.sleep(pollInterval);
    }

    throw new Error(
      `Scan ${scanId} timed out after ${timeoutSeconds}s. The scan may still be running — check the dashboard.`
    );
  }

  async postWebhook(payload: WebhookPayload): Promise<void> {
    try {
      await this.http.post("/api/v2/github/webhook", payload);
      core.info("IaC findings sent to Fortly webhook");
    } catch (error) {
      core.warning(
        `Failed to post IaC webhook: ${this.extractMessage(error)}. Continuing without IaC results.`
      );
    }
  }

  async downloadSarif(scanId: string): Promise<SarifReport> {
    try {
      const response = await this.http.get<SarifReport>(
        `/api/v2/scans/${scanId}/report?format=sarif`
      );
      return response.data;
    } catch (error) {
      throw this.wrapError("Failed to download SARIF report", error);
    }
  }

  async batchRemediate(input: {
    scanId: string;
    vulnIds: string[];
    repoUrl: string;
    branch: string;
    githubToken: string;
    minSeverity?: string;
  }): Promise<{
    totalFixed: number;
    totalFailed: number;
    prUrl?: string;
    prNumber?: number;
    fixes: Array<{ vulnId: string; status: string; error?: string }>;
  }> {
    try {
      const response = await this.http.post("/api/v2/remediate/batch", input);
      return response.data;
    } catch (error) {
      throw this.wrapError("Failed to batch remediate", error);
    }
  }

  getReportUrl(scanId: string): string {
    return `${this.baseUrl}/scans/${scanId}`;
  }

  private wrapError(context: string, error: unknown): Error {
    const message = this.extractMessage(error);
    return new Error(`${context}: ${message}`);
  }

  private extractMessage(error: unknown): string {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      const body = error.response?.data;
      const detail =
        typeof body === "object" && body !== null && "message" in body
          ? (body as { message: string }).message
          : JSON.stringify(body);

      if (status === 401) {
        return "Invalid API key. Check your api-key input.";
      }
      if (status === 403) {
        return "API key does not have permission for this operation.";
      }
      if (status === 404) {
        return "Resource not found. Verify your api-url input.";
      }
      return `HTTP ${status}: ${detail}`;
    }
    if (error instanceof Error) {
      return error.message;
    }
    return String(error);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
