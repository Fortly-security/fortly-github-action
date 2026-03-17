type Octokit = ReturnType<typeof import("@actions/github").getOctokit>;
type Context = typeof import("@actions/github").context;
export declare class StatusCheckManager {
    private octokit;
    private context;
    private checkRunId;
    constructor(octokit: Octokit, context: Context);
    private getHeadSha;
    createPending(description: string): Promise<void>;
    createSuccess(description: string): Promise<void>;
    createFailure(description: string): Promise<void>;
    private completeCheck;
}
export {};
