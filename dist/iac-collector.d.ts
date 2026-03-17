import { IacFile } from "./types";
export declare function isIacFile(filename: string): boolean;
type Octokit = ReturnType<typeof import("@actions/github").getOctokit>;
type Context = typeof import("@actions/github").context;
export declare class IacCollector {
    private octokit;
    private context;
    constructor(octokit: Octokit, context: Context);
    collectFromPR(): Promise<IacFile[]>;
}
export {};
