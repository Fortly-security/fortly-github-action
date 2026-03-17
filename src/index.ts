import * as core from "@actions/core";
import * as github from "@actions/github";
import * as fs from "fs";
import * as path from "path";
import { FortlyClient } from "./client";
import { CommentBuilder } from "./comment-builder";
import { IacCollector } from "./iac-collector";
import { SarifBuilder } from "./sarif-builder";
import { StatusCheckManager } from "./status-check";
import { SecretScanner, SecretFinding } from "./secret-scanner";
import { ScaScanner, isLockfile } from "./sca-scanner";
import { SastScanner } from "./sast-scanner";
import { IacFile } from "./types";

async function run(): Promise<void> {
  try {
    const apiKey = core.getInput("api-key");
    const targetUrl = core.getInput("target-url");
    const failThreshold = parseInt(core.getInput("fail-threshold") || "60", 10);
    const scanIac = core.getInput("scan-iac") === "true";
    const scanMode = core.getInput("scan-mode") || "quick";
    const commentOnPr = core.getInput("comment-on-pr") === "true";
    const apiUrl = core.getInput("api-url") || "https://api.fortly.io";
    const uploadSarif = core.getInput("upload-sarif") !== "false";
    const scanSecrets = core.getInput("scan-secrets") !== "false";
    const scanDeps = core.getInput("scan-deps") !== "false";
    const scanSast = core.getInput("scan-sast") !== "false";

    const context = github.context;
    const token = process.env.GITHUB_TOKEN || "";
    const octokit = github.getOctokit(token);

    const localOnlyMode = !apiKey || !targetUrl;
    const statusCheck = new StatusCheckManager(octokit, context);

    // 1. Create pending status check
    await statusCheck.createPending(localOnlyMode ? "Fortly local scan running..." : "Fortly is scanning...");

    // 2. Collect IaC files from PR diff (if enabled)
    let iacFiles: IacFile[] = [];
    if (scanIac && context.payload.pull_request) {
      const collector = new IacCollector(octokit, context);
      iacFiles = await collector.collectFromPR();
      core.info(`Found ${iacFiles.length} IaC files in PR`);
    }

    // 3. Scan for secrets in PR diff (if enabled)
    let secretFindings: SecretFinding[] = [];
    if (scanSecrets && context.payload.pull_request) {
      try {
        const { data: prFiles } = await octokit.rest.pulls.listFiles({
          ...context.repo,
          pull_number: context.payload.pull_request.number,
          per_page: 100,
        });

        const filesToScan: { filename: string; content: string }[] = [];
        for (const file of prFiles.filter(f => f.status !== "removed").slice(0, 50)) {
          try {
            const { data } = await octokit.rest.repos.getContent({
              ...context.repo,
              path: file.filename,
              ref: context.payload.pull_request.head.sha,
            });
            if ("content" in data && typeof data.content === "string") {
              filesToScan.push({
                filename: file.filename,
                content: Buffer.from(data.content, "base64").toString("utf-8"),
              });
            }
          } catch {
            // Skip files that can't be fetched
          }
        }

        secretFindings = SecretScanner.scan(filesToScan);

        if (secretFindings.length > 0) {
          core.warning(`Found ${secretFindings.length} secret(s) in PR files`);

          // Post secret findings as PR comment
          const secretComment = SecretScanner.buildPrComment(secretFindings);
          if (secretComment) {
            await octokit.rest.issues.createComment({
              ...context.repo,
              issue_number: context.payload.pull_request.number,
              body: secretComment,
            });
          }

          core.setOutput("secrets-found", secretFindings.length.toString());
        } else {
          core.info("No secrets detected in PR files");
          core.setOutput("secrets-found", "0");
        }
      } catch (secretError: any) {
        core.warning(`Secret scanning failed: ${secretError.message}. Continuing with DAST scan.`);
        core.setOutput("secrets-found", "0");
      }
    }

    // 4. Scan dependencies for vulnerabilities (if enabled)
    if (scanDeps) {
      try {
        // Find lockfiles in the repo root
        const lockfileNames = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "go.sum", "Gemfile.lock", "Cargo.lock", "composer.lock"];
        const lockfiles: { filename: string; content: string }[] = [];

        for (const name of lockfileNames) {
          try {
            const { data } = await octokit.rest.repos.getContent({
              ...context.repo,
              path: name,
              ref: context.payload.pull_request?.head?.sha ?? context.sha,
            });
            if ("content" in data && typeof data.content === "string") {
              lockfiles.push({
                filename: name,
                content: Buffer.from(data.content, "base64").toString("utf-8"),
              });
            }
          } catch {
            // File doesn't exist, skip
          }
        }

        if (lockfiles.length > 0) {
          core.info(`Found ${lockfiles.length} lockfile(s), scanning dependencies...`);
          const scaResult = await ScaScanner.scan(lockfiles);

          core.setOutput("dependencies-total", scaResult.summary.total.toString());
          core.setOutput("dependencies-vulnerable", scaResult.summary.vulnerable.toString());

          if (scaResult.findings.length > 0) {
            core.warning(`Found ${scaResult.findings.length} vulnerable dependencies`);

            if (commentOnPr && context.payload.pull_request) {
              const scaComment = ScaScanner.buildPrComment(scaResult.findings, scaResult.summary.total);
              if (scaComment) {
                await octokit.rest.issues.createComment({
                  ...context.repo,
                  issue_number: context.payload.pull_request.number,
                  body: scaComment,
                });
              }
            }
          } else {
            core.info(`${scaResult.summary.total} dependencies scanned, no vulnerabilities found`);
          }
        } else {
          core.info("No lockfiles found in repository root");
          core.setOutput("dependencies-total", "0");
          core.setOutput("dependencies-vulnerable", "0");
        }
      } catch (scaError: any) {
        core.warning(`SCA scan failed: ${scaError.message}. Continuing with DAST scan.`);
        core.setOutput("dependencies-total", "0");
        core.setOutput("dependencies-vulnerable", "0");
      }
    }

    // 5. Static code analysis on PR files (if enabled)
    if (scanSast && context.payload.pull_request) {
      try {
        const { data: prFiles } = await octokit.rest.pulls.listFiles({
          ...context.repo,
          pull_number: context.payload.pull_request.number,
          per_page: 100,
        });

        const codeFiles: { filename: string; content: string }[] = [];
        const codeExts = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".py", ".java", ".go"];
        const filesToFetch = prFiles
          .filter(f => f.status !== "removed")
          .filter(f => codeExts.some(ext => f.filename.endsWith(ext)))
          .slice(0, 50);

        for (const file of filesToFetch) {
          try {
            const { data } = await octokit.rest.repos.getContent({
              ...context.repo,
              path: file.filename,
              ref: context.payload.pull_request.head.sha,
            });
            if ("content" in data && typeof data.content === "string") {
              codeFiles.push({
                filename: file.filename,
                content: Buffer.from(data.content, "base64").toString("utf-8"),
              });
            }
          } catch { /* skip */ }
        }

        if (codeFiles.length > 0) {
          const sastFindings = SastScanner.scan(codeFiles);
          core.setOutput("sast-findings", sastFindings.length.toString());

          if (sastFindings.length > 0) {
            core.warning(`SAST: Found ${sastFindings.length} code security issue(s)`);
            if (commentOnPr) {
              const sastComment = SastScanner.buildPrComment(sastFindings);
              if (sastComment) {
                await octokit.rest.issues.createComment({
                  ...context.repo,
                  issue_number: context.payload.pull_request.number,
                  body: sastComment,
                });
              }
            }
          } else {
            core.info(`SAST: ${codeFiles.length} files scanned, no issues found`);
          }
        } else {
          core.info("SAST: No code files changed in PR");
          core.setOutput("sast-findings", "0");
        }
      } catch (sastError: any) {
        core.warning(`SAST scan failed: ${sastError.message}. Continuing.`);
        core.setOutput("sast-findings", "0");
      }
    }

    // DAST scan + API-dependent steps (requires API key + target URL)
    if (!localOnlyMode) {
      const client = new FortlyClient(apiUrl, apiKey);

      // 6. Create scan
      core.info(`Starting ${scanMode} scan on ${targetUrl}...`);
      const scan = await client.createScan(targetUrl, scanMode);
      core.info(`Scan created: ${scan.scanId}`);

      // 7. Wait for scan completion (polling)
      const result = await client.waitForCompletion(
        scan.scanId,
        scanMode === "quick" ? 60 : 300
      );
      core.info(`Scan completed. Score: ${result.score}/100 (${result.grade})`);

      // 8. Generate and upload SARIF
      const sarifPath = path.join(process.env.RUNNER_TEMP || "/tmp", `fortly-${scan.scanId}.sarif`);
      let sarifReport;
      try {
        sarifReport = await client.downloadSarif(scan.scanId);
        core.info("SARIF report downloaded from Fortly API");
      } catch {
        core.warning("Failed to download SARIF from API, building locally...");
        sarifReport = SarifBuilder.build(result, scan.scanId, apiUrl);
      }
      fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
      core.setOutput("sarif-file", sarifPath);
      core.info(`SARIF file written to ${sarifPath}`);

      if (uploadSarif && token) {
        try {
          const sarifContent = fs.readFileSync(sarifPath, "utf-8");
          const zlib = await import("zlib");
          const gzipped = zlib.gzipSync(Buffer.from(sarifContent));
          const base64Sarif = gzipped.toString("base64");

          await octokit.request("POST /repos/{owner}/{repo}/code-scanning/sarifs", {
            owner: context.repo.owner,
            repo: context.repo.repo,
            commit_sha: context.payload.pull_request?.head?.sha ?? context.sha,
            ref: context.ref,
            sarif: base64Sarif,
          });
          core.info("SARIF uploaded to GitHub Security tab");
        } catch (uploadError: any) {
          core.warning(
            `Failed to upload SARIF to GitHub: ${uploadError.message}. ` +
            `Ensure the workflow has 'security-events: write' permission.`
          );
        }
      }

      // 9. Post IaC findings via webhook (if applicable)
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

      // 10. Post PR comment with DAST results
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

      // 11. Set outputs
      const passed = result.score >= failThreshold;
      core.setOutput("score", result.score.toString());
      core.setOutput("grade", result.grade);
      core.setOutput("vulnerabilities", result.summary.totalVulnerabilities.toString());
      core.setOutput("critical-count", result.summary.critical.toString());
      core.setOutput("high-count", result.summary.high.toString());
      core.setOutput("scan-url", `${apiUrl}/scans/${scan.scanId}`);
      core.setOutput("passed", passed.toString());

      // 12. Update status check
      if (passed) {
        await statusCheck.createSuccess(
          `Score: ${result.score}/100 (${result.grade}) — ${result.summary.totalVulnerabilities} vulnerabilities`
        );
      } else {
        await statusCheck.createFailure(
          `Score: ${result.score}/100 (${result.grade}) — Below threshold ${failThreshold}`
        );
      }

      // 13. Fail the action if below threshold
      if (!passed) {
        core.setFailed(
          `Security score ${result.score} is below threshold ${failThreshold}`
        );
      }

      // 14. Auto-remediate if enabled and scan found vulnerabilities
      const autoRemediate = core.getInput("auto-remediate") === "true";
      const remediateSeverity = core.getInput("remediate-severity") || "high";

      if (autoRemediate && result.vulnerabilities && result.vulnerabilities.length > 0) {
        try {
          const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
          const minSevNum = severityOrder[remediateSeverity.toUpperCase()] ?? 1;

          const vulnsToFix = result.vulnerabilities.filter(
            (v) => (severityOrder[v.severity] ?? 3) <= minSevNum
          );

          if (vulnsToFix.length > 0 && context.payload.pull_request) {
            core.info(`Auto-remediating ${vulnsToFix.length} vulnerabilities (${remediateSeverity}+)...`);

            const repoUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}`;
            const branch = context.payload.pull_request.head.ref;

            const batchResult = await client.batchRemediate({
              scanId: scan.scanId,
              vulnIds: vulnsToFix.map((_, i) => `vuln-${scan.scanId}-${i}`),
              repoUrl,
              branch,
              githubToken: token,
              minSeverity: remediateSeverity,
            });

            core.setOutput("remediation-pr", batchResult.prUrl || "");
            core.setOutput("fixes-count", batchResult.totalFixed.toString());

            if (batchResult.prUrl) {
              core.info(`Remediation PR created: ${batchResult.prUrl} (${batchResult.totalFixed} fixes)`);
            } else {
              core.info(`Auto-remediation completed: ${batchResult.totalFixed} fixed, ${batchResult.totalFailed} failed`);
            }
          } else {
            core.setOutput("remediation-pr", "");
            core.setOutput("fixes-count", "0");
          }
        } catch (remError: any) {
          core.warning(`Auto-remediation failed: ${remError.message}. Scan results are still valid.`);
          core.setOutput("remediation-pr", "");
          core.setOutput("fixes-count", "0");
        }
      }
    } else {
      // Local-only mode: no API key or target URL provided
      core.info("No API key or target URL — running in local-only mode (secrets + SCA + SAST)");

      // Set DAST-related outputs to N/A / defaults
      core.setOutput("score", "N/A");
      core.setOutput("grade", "N/A");
      core.setOutput("vulnerabilities", "0");
      core.setOutput("critical-count", "0");
      core.setOutput("high-count", "0");
      core.setOutput("scan-url", "");
      core.setOutput("remediation-pr", "");
      core.setOutput("fixes-count", "0");
      core.setOutput("sarif-file", "");

      // Fail if secrets were found (critical severity)
      if (secretFindings.length > 0) {
        await statusCheck.createFailure(
          `Local scan: ${secretFindings.length} secret(s) found in PR files`
        );
        core.setFailed(
          `${secretFindings.length} secret(s) detected in PR files. Remove them before merging.`
        );
      } else {
        await statusCheck.createSuccess("Local scan passed (secrets + SCA + SAST)");
        core.setOutput("passed", "true");
      }
    }
  } catch (error: any) {
    core.setFailed(error.message);
  }
}

run();
