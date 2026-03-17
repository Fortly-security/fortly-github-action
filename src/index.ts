import * as core from "@actions/core";
import * as github from "@actions/github";
import { FortlyClient } from "./client";
import { CommentBuilder } from "./comment-builder";
import { IacCollector } from "./iac-collector";
import { StatusCheckManager } from "./status-check";
import { IacFile } from "./types";

async function run(): Promise<void> {
  try {
    const apiKey = core.getInput("api-key", { required: true });
    const targetUrl = core.getInput("target-url", { required: true });
    const failThreshold = parseInt(core.getInput("fail-threshold") || "60", 10);
    const scanIac = core.getInput("scan-iac") === "true";
    const scanMode = core.getInput("scan-mode") || "quick";
    const commentOnPr = core.getInput("comment-on-pr") === "true";
    const apiUrl = core.getInput("api-url") || "https://api.fortly.io";

    const context = github.context;
    const token = process.env.GITHUB_TOKEN || "";
    const octokit = github.getOctokit(token);

    const client = new FortlyClient(apiUrl, apiKey);
    const statusCheck = new StatusCheckManager(octokit, context);

    // 1. Create pending status check
    await statusCheck.createPending("Fortly is scanning...");

    // 2. Collect IaC files from PR diff (if enabled)
    let iacFiles: IacFile[] = [];
    if (scanIac && context.payload.pull_request) {
      const collector = new IacCollector(octokit, context);
      iacFiles = await collector.collectFromPR();
      core.info(`Found ${iacFiles.length} IaC files in PR`);
    }

    // 3. Create scan
    core.info(`Starting ${scanMode} scan on ${targetUrl}...`);
    const scan = await client.createScan(targetUrl, scanMode);
    core.info(`Scan created: ${scan.scanId}`);

    // 4. Wait for scan completion (polling)
    const result = await client.waitForCompletion(
      scan.scanId,
      scanMode === "quick" ? 60 : 300
    );
    core.info(`Scan completed. Score: ${result.score}/100 (${result.grade})`);

    // 5. Post IaC findings via webhook (if applicable)
    if (iacFiles.length > 0 && context.payload.pull_request) {
      await client.postWebhook({
        scanId: scan.scanId,
        repoOwner: context.repo.owner,
        repoName: context.repo.repo,
        prNumber: context.payload.pull_request.number,
        githubToken: token,
        iacFiles,
      });
    }

    // 6. Post PR comment
    if (commentOnPr && context.payload.pull_request) {
      const comment = CommentBuilder.build(
        result,
        scan.scanId,
        apiUrl,
        iacFiles.length
      );
      await octokit.rest.issues.createComment({
        ...context.repo,
        issue_number: context.payload.pull_request.number,
        body: comment,
      });
      core.info("PR comment posted");
    }

    // 7. Set outputs
    const passed = result.score >= failThreshold;
    core.setOutput("score", result.score.toString());
    core.setOutput("grade", result.grade);
    core.setOutput("vulnerabilities", result.summary.totalVulnerabilities.toString());
    core.setOutput("critical-count", result.summary.critical.toString());
    core.setOutput("high-count", result.summary.high.toString());
    core.setOutput("scan-url", `${apiUrl}/scans/${scan.scanId}`);
    core.setOutput("passed", passed.toString());

    // 8. Update status check
    if (passed) {
      await statusCheck.createSuccess(
        `Score: ${result.score}/100 (${result.grade}) — ${result.summary.totalVulnerabilities} vulnerabilities`
      );
    } else {
      await statusCheck.createFailure(
        `Score: ${result.score}/100 (${result.grade}) — Below threshold ${failThreshold}`
      );
    }

    // 9. Fail the action if below threshold
    if (!passed) {
      core.setFailed(
        `Security score ${result.score} is below threshold ${failThreshold}`
      );
    }
  } catch (error: any) {
    core.setFailed(error.message);
  }
}

run();
