import axios from "axios";
import { FortlyClient } from "../client";

jest.mock("axios");
jest.mock("@actions/core", () => ({
  info: jest.fn(),
  warning: jest.fn(),
}));

const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("FortlyClient.batchRemediate", () => {
  let client: FortlyClient;
  const mockAxiosInstance = {
    get: jest.fn(),
    post: jest.fn(),
    request: jest.fn(),
    interceptors: {
      response: { use: jest.fn() },
      request: { use: jest.fn() },
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAxios.create.mockReturnValue(mockAxiosInstance as any);
    mockedAxios.isAxiosError.mockReturnValue(false);
    client = new FortlyClient("https://api.fortly.io", "test-key");
  });

  it("calls POST /api/v2/remediate/batch with correct payload", async () => {
    const mockResponse = {
      totalFixed: 3,
      totalFailed: 1,
      prUrl: "https://github.com/owner/repo/pull/42",
      prNumber: 42,
      fixes: [
        { vulnId: "v1", status: "fixed" },
        { vulnId: "v2", status: "fixed" },
        { vulnId: "v3", status: "fixed" },
        { vulnId: "v4", status: "failed", error: "LLM error" },
      ],
    };
    mockAxiosInstance.post.mockResolvedValue({ data: mockResponse });

    const result = await client.batchRemediate({
      scanId: "scan-123",
      vulnIds: ["v1", "v2", "v3", "v4"],
      repoUrl: "https://github.com/owner/repo",
      branch: "main",
      githubToken: "ghp_token",
      minSeverity: "high",
    });

    expect(mockAxiosInstance.post).toHaveBeenCalledWith(
      "/api/v2/remediate/batch",
      expect.objectContaining({ scanId: "scan-123" })
    );
    expect(result.totalFixed).toBe(3);
    expect(result.prUrl).toBe("https://github.com/owner/repo/pull/42");
  });

  it("throws descriptive error on failure", async () => {
    mockAxiosInstance.post.mockRejectedValue(new Error("Server error"));
    await expect(
      client.batchRemediate({
        scanId: "scan-456",
        vulnIds: ["v1"],
        repoUrl: "https://github.com/owner/repo",
        branch: "main",
        githubToken: "ghp_token",
      })
    ).rejects.toThrow("Failed to batch remediate");
  });
});
