import * as core from "@actions/core";
import { Annotation } from "./annotation-builder";

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

  async createSuccess(
    description: string,
    annotations: Annotation[] = []
  ): Promise<void> {
    await this.completeCheck("success", description, annotations);
  }

  async createFailure(
    description: string,
    annotations: Annotation[] = []
  ): Promise<void> {
    await this.completeCheck("failure", description, annotations);
  }

  private async completeCheck(
    conclusion: "success" | "failure",
    description: string,
    annotations: Annotation[] = []
  ): Promise<void> {
    if (this.checkRunId === null) {
      core.warning("No check run ID — skipping status update");
      return;
    }

    try {
      // GitHub limits to 50 annotations per API call, so batch them
      const batches: Annotation[][] = [];
      for (let i = 0; i < annotations.length; i += 50) {
        batches.push(annotations.slice(i, i + 50));
      }

      // First update completes the check run with the first batch of annotations
      await this.octokit.rest.checks.update({
        ...this.context.repo,
        check_run_id: this.checkRunId,
        status: "completed",
        conclusion,
        output: {
          title: CHECK_NAME,
          summary: description,
          annotations: batches[0] || [],
        },
      });

      // Send additional batches (if more than 50 annotations)
      for (let i = 1; i < batches.length; i++) {
        await this.octokit.rest.checks.update({
          ...this.context.repo,
          check_run_id: this.checkRunId,
          output: {
            title: CHECK_NAME,
            summary: description,
            annotations: batches[i],
          },
        });
      }

      const annotationCount = annotations.length;
      const annotationMsg =
        annotationCount > 0 ? ` (${annotationCount} annotations)` : "";
      core.info(
        `Check run updated: ${conclusion} — ${description}${annotationMsg}`
      );
    } catch (error) {
      core.warning(`Failed to update check run: ${error}`);
    }
  }
}
