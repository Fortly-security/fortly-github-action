import * as core from "@actions/core";
import { IacFile } from "./types";

const IAC_PATTERNS: RegExp[] = [
  /\.tf$/,
  /\.tfvars$/,
  /Dockerfile(\..*)?$/,
  /docker-compose\.ya?ml$/,
  /\.env$/,
  /\.env\..+$/,
  /cloudformation\.ya?ml$/,
  /cloudformation\.json$/,
  /template\.ya?ml$/,
  /\.helmignore$/,
  /Chart\.ya?ml$/,
  /values\.ya?ml$/,
];

const K8S_PATH_PATTERNS: RegExp[] = [
  /k8s\//,
  /kubernetes\//,
  /deploy\//,
  /manifests\//,
  /helm\//,
  /charts\//,
  /infra\//,
];

const MAX_FILES = 20;

export function isIacFile(filename: string): boolean {
  if (IAC_PATTERNS.some((p) => p.test(filename))) {
    return true;
  }

  // YAML/YML files in infrastructure-related directories
  if (/\.ya?ml$/.test(filename) && K8S_PATH_PATTERNS.some((p) => p.test(filename))) {
    return true;
  }

  return false;
}

type Octokit = ReturnType<typeof import("@actions/github").getOctokit>;
type Context = typeof import("@actions/github").context;

export class IacCollector {
  private octokit: Octokit;
  private context: Context;

  constructor(octokit: Octokit, context: Context) {
    this.octokit = octokit;
    this.context = context;
  }

  async collectFromPR(): Promise<IacFile[]> {
    const pr = this.context.payload.pull_request;
    if (!pr) {
      core.info("No pull request context — skipping IaC collection");
      return [];
    }

    // List files changed in the PR
    const { data: files } = await this.octokit.rest.pulls.listFiles({
      ...this.context.repo,
      pull_number: pr.number,
      per_page: 100,
    });

    const iacFilenames = files
      .filter((f) => f.status !== "removed")
      .filter((f) => isIacFile(f.filename))
      .map((f) => f.filename)
      .slice(0, MAX_FILES);

    if (iacFilenames.length === 0) {
      return [];
    }

    core.info(
      `Collecting ${iacFilenames.length} IaC file(s): ${iacFilenames.join(", ")}`
    );

    const results: IacFile[] = [];

    for (const filename of iacFilenames) {
      try {
        const { data } = await this.octokit.rest.repos.getContent({
          ...this.context.repo,
          path: filename,
          ref: pr.head.sha,
        });

        if ("content" in data && typeof data.content === "string") {
          const content = Buffer.from(data.content, "base64").toString("utf-8");
          results.push({ filename, content });
        }
      } catch (error) {
        core.warning(`Failed to fetch IaC file ${filename}: ${error}`);
      }
    }

    return results;
  }
}
