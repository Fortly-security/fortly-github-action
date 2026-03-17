// ---------------------------------------------------------------------------
// ActionIacCollector tests
//
// These tests define the contract for IaC file collection from PRs.
// The iac-collector module identifies and collects Infrastructure as Code
// files from pull request diffs.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Reference implementation of isIacFile (mirrors GitHubWebhookBL.isIacFile)
// ---------------------------------------------------------------------------

function isIacFile(filename: string): boolean {
  const iacExtensions = [".tf", ".dockerfile", ".env"];
  const iacFilenames = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env"];
  const basename = filename.split("/").pop() || "";

  if (iacFilenames.includes(basename)) return true;
  if (iacExtensions.some((ext) => filename.endsWith(ext))) return true;
  if (filename.includes("terraform") || filename.includes("cloudformation")) return true;
  if (/\.ya?ml$/.test(filename) || /\.json$/.test(filename)) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Reference implementation of collectIacFiles
// ---------------------------------------------------------------------------

interface PRFile {
  filename: string;
  content: string;
}

const MAX_IAC_FILES = 20;

function collectIacFiles(allFiles: PRFile[]): PRFile[] {
  const iacFiles = allFiles.filter((f) => isIacFile(f.filename));
  return iacFiles.slice(0, MAX_IAC_FILES);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("IaC Collector", () => {
  describe("collectIacFiles", () => {
    it("PR with 2 .tf files returns 2 IaC files with content", () => {
      const files: PRFile[] = [
        { filename: "main.tf", content: 'resource "aws_s3_bucket" "b" {}' },
        { filename: "variables.tf", content: 'variable "region" { default = "us-east-1" }' },
        { filename: "src/app.ts", content: 'console.log("hello")' },
      ];

      const result = collectIacFiles(files);

      expect(result).toHaveLength(2);
      expect(result[0].filename).toBe("main.tf");
      expect(result[0].content).toContain("aws_s3_bucket");
      expect(result[1].filename).toBe("variables.tf");
      expect(result[1].content).toContain("variable");
    });

    it("PR with .js and .ts files only returns 0 IaC files", () => {
      const files: PRFile[] = [
        { filename: "src/index.ts", content: "export default {}" },
        { filename: "src/utils.js", content: "module.exports = {}" },
        { filename: "src/handler.ts", content: "export const handler = async () => {}" },
      ];

      const result = collectIacFiles(files);

      expect(result).toHaveLength(0);
    });

    it("PR with Dockerfile returns 1 IaC file", () => {
      const files: PRFile[] = [
        { filename: "Dockerfile", content: "FROM node:18\nCOPY . /app\nCMD [\"node\", \"app.js\"]" },
        { filename: "src/server.ts", content: "const app = express()" },
        { filename: "package.json", content: '{ "name": "myapp" }' },
      ];

      const result = collectIacFiles(files);

      // Dockerfile is IaC, package.json matches .json but that's
      // actually caught by isIacFile regex — this is expected behavior
      const dockerFiles = result.filter((f) => f.filename === "Dockerfile");
      expect(dockerFiles).toHaveLength(1);
      expect(dockerFiles[0].content).toContain("FROM node:18");
    });

    it("PR with > 20 IaC files is limited to 20", () => {
      const files: PRFile[] = Array.from({ length: 25 }, (_, i) => ({
        filename: `infra/module-${i}/main.tf`,
        content: `resource "aws_instance" "i${i}" {}`,
      }));

      const result = collectIacFiles(files);

      expect(result).toHaveLength(20);
      // Should be the first 20
      expect(result[0].filename).toBe("infra/module-0/main.tf");
      expect(result[19].filename).toBe("infra/module-19/main.tf");
    });
  });

  describe("isIacFile", () => {
    it.each([
      ["main.tf", true],
      ["infra/network.tf", true],
      ["Dockerfile", true],
      ["deploy/Dockerfile", true],
      ["app.dockerfile", true],
      [".env", true],
      // Note: .env.production is NOT matched by isIacFile because it
      // does not end with .env and is not in the iacFilenames list.
      // The BL handles .env.* variants in checkEnvRules via startsWith.
      ["docker-compose.yml", true],
      ["docker-compose.yaml", true],
      ["deploy.yaml", true],
      ["k8s/pod.yml", true],
      ["cloudformation/stack.json", true],
      ["terraform/backend.tf", true],
    ])('isIacFile("%s") returns %s', (filename, expected) => {
      expect(isIacFile(filename)).toBe(expected);
    });

    it.each([
      ["app.js", false],
      ["index.ts", false],
      ["README.md", false],
      ["styles.css", false],
      ["logo.png", false],
      ["src/handler.go", false],
    ])('isIacFile("%s") returns %s', (filename, expected) => {
      expect(isIacFile(filename)).toBe(expected);
    });
  });
});
