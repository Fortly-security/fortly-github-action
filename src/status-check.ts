import * as core from "@actions/core";

type Octokit = ReturnType<typeof import("@actions/github").getOctokit>;
type Context = typeof import("@actions/github").context;

const CHECK_NAME = "Fortly Security Scan";

export class StatusCheckManager {
  private octokit: Octokit;
  private context: Context;
  private checkRunId: number | null = null;

  constructor(octokit: Octokit, context: Context) {
    this.octokit = octokit;
    this.context = context;
  }

  private getHeadSha(): string {
    return (
      this.context.payload.pull_request?.head?.sha ?? this.context.sha
    );
  }

  async createPending(description: string): Promise<void> {
    try {
      const { data } = await this.octokit.rest.checks.create({
        ...this.context.repo,
        name: CHECK_NAME,
        head_sha: this.getHeadSha(),
        status: "in_progress",
        output: {
          title: CHECK_NAME,
          summary: description,
        },
      });
      this.checkRunId = data.id;
      core.info(`Check run created: ${data.id}`);
    } catch (error) {
      core.warning(`Failed to create check run: ${error}. Continuing without status checks.`);
    }
  }

  async createSuccess(description: string): Promise<void> {
    await this.completeCheck("success", description);
  }

  async createFailure(description: string): Promise<void> {
    await this.completeCheck("failure", description);
  }

  private async completeCheck(
    conclusion: "success" | "failure",
    description: string
  ): Promise<void> {
    if (this.checkRunId === null) {
      core.warning("No check run ID — skipping status update");
      return;
    }

    try {
      await this.octokit.rest.checks.update({
        ...this.context.repo,
        check_run_id: this.checkRunId,
        status: "completed",
        conclusion,
        output: {
          title: CHECK_NAME,
          summary: description,
        },
      });
      core.info(`Check run updated: ${conclusion} — ${description}`);
    } catch (error) {
      core.warning(`Failed to update check run: ${error}`);
    }
  }
}
