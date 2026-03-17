import { ScanResult } from "./types";
export declare class CommentBuilder {
    static build(result: ScanResult, scanId: string, apiUrl: string, iacFileCount: number): string;
    private static severityIcon;
}
