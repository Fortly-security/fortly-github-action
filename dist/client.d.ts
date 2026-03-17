import { CreateScanResponse, ScanResult, WebhookPayload } from "./types";
export declare class FortlyClient {
    private http;
    constructor(baseUrl: string, apiKey: string);
    createScan(targetUrl: string, mode: string): Promise<CreateScanResponse>;
    getScan(scanId: string): Promise<ScanResult>;
    waitForCompletion(scanId: string, timeoutSeconds: number): Promise<ScanResult>;
    postWebhook(payload: WebhookPayload): Promise<void>;
    private wrapError;
    private extractMessage;
    private sleep;
}
