import axios from "axios";
import { FortlyClient } from "../client";

jest.mock("axios");
jest.mock("@actions/core", () => ({
  info: jest.fn(),
  warning: jest.fn(),
}));

const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("FortlyClient.downloadSarif", () => {
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

  it("calls GET /api/v2/scans/{scanId}/report?format=sarif", async () => {
    const mockSarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [],
    };
    mockAxiosInstance.get.mockResolvedValue({ data: mockSarif });

    const result = await client.downloadSarif("scan-123");

    expect(mockAxiosInstance.get).toHaveBeenCalledWith("/api/v2/scans/scan-123/report?format=sarif");
    expect(result).toEqual(mockSarif);
  });

  it("throws descriptive error on failure", async () => {
    mockAxiosInstance.get.mockRejectedValue(new Error("Network error"));

    await expect(client.downloadSarif("scan-456")).rejects.toThrow("Failed to download SARIF report");
  });
});
