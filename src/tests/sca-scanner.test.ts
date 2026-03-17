import { ScaScanner, parseLockfile, isLockfile } from "../sca-scanner";

// Mock axios to avoid real OSV.dev calls
jest.mock("axios", () => ({
  post: jest.fn().mockResolvedValue({ data: { results: [] } }),
  default: { post: jest.fn().mockResolvedValue({ data: { results: [] } }) },
}));

jest.mock("@actions/core", () => ({
  info: jest.fn(),
  warning: jest.fn(),
}));

describe("SCA Scanner", () => {
  describe("isLockfile", () => {
    it.each([
      ["package-lock.json", true],
      ["yarn.lock", true],
      ["requirements.txt", true],
      ["go.sum", true],
      ["Gemfile.lock", true],
      ["Cargo.lock", true],
      ["composer.lock", true],
      ["Pipfile.lock", true],
      ["pnpm-lock.yaml", true],
      ["src/app.ts", false],
      ["README.md", false],
      ["package.json", false],  // NOT a lockfile
    ])("isLockfile('%s') returns %s", (filename, expected) => {
      expect(isLockfile(filename)).toBe(expected);
    });
  });

  describe("parseLockfile", () => {
    it("parses package-lock.json v2 format", () => {
      const content = JSON.stringify({
        packages: {
          "": { name: "myapp", version: "1.0.0" },
          "node_modules/express": { version: "4.18.2" },
          "node_modules/lodash": { version: "4.17.21" },
        },
      });
      const deps = parseLockfile("package-lock.json", content);
      expect(deps.length).toBe(2);
      expect(deps[0].name).toBe("express");
      expect(deps[0].version).toBe("4.18.2");
      expect(deps[0].ecosystem).toBe("npm");
    });

    it("parses package-lock.json v1 format", () => {
      const content = JSON.stringify({
        dependencies: {
          express: { version: "4.18.2" },
          lodash: { version: "4.17.21" },
        },
      });
      const deps = parseLockfile("package-lock.json", content);
      expect(deps.length).toBe(2);
    });

    it("parses requirements.txt", () => {
      const content = `
flask==2.3.0
requests==2.31.0
# comment
-e git+https://github.com/user/repo.git#egg=mypackage
numpy==1.24.0
`;
      const deps = parseLockfile("requirements.txt", content);
      expect(deps.length).toBe(3);
      expect(deps[0].name).toBe("flask");
      expect(deps[0].version).toBe("2.3.0");
      expect(deps[0].ecosystem).toBe("PyPI");
    });

    it("parses go.sum", () => {
      const content = `
github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
github.com/stretchr/testify v1.8.4 h1:ghi=
`;
      const deps = parseLockfile("go.sum", content);
      expect(deps.length).toBe(2);  // deduplicated
      expect(deps[0].name).toBe("github.com/gin-gonic/gin");
      expect(deps[0].version).toBe("1.9.1");
      expect(deps[0].ecosystem).toBe("Go");
    });

    it("parses Cargo.lock", () => {
      const content = `
[[package]]
name = "serde"
version = "1.0.188"

[[package]]
name = "tokio"
version = "1.32.0"
`;
      const deps = parseLockfile("Cargo.lock", content);
      expect(deps.length).toBe(2);
      expect(deps[0].name).toBe("serde");
      expect(deps[0].ecosystem).toBe("crates.io");
    });

    it("parses composer.lock", () => {
      const content = JSON.stringify({
        packages: [
          { name: "laravel/framework", version: "v10.0.0" },
          { name: "monolog/monolog", version: "v3.4.0" },
        ],
      });
      const deps = parseLockfile("composer.lock", content);
      expect(deps.length).toBe(2);
      expect(deps[0].name).toBe("laravel/framework");
      expect(deps[0].version).toBe("10.0.0");  // v prefix stripped
    });

    it("parses Pipfile.lock", () => {
      const content = JSON.stringify({
        default: {
          flask: { version: "==2.3.0" },
          requests: { version: "==2.31.0" },
        },
      });
      const deps = parseLockfile("Pipfile.lock", content);
      expect(deps.length).toBe(2);
      expect(deps[0].name).toBe("flask");
      expect(deps[0].version).toBe("2.3.0");  // == prefix stripped
    });

    it("returns empty for unknown file", () => {
      expect(parseLockfile("README.md", "hello")).toHaveLength(0);
    });

    it("returns empty for invalid JSON", () => {
      expect(parseLockfile("package-lock.json", "not json")).toHaveLength(0);
    });
  });

  describe("ScaScanner.scan", () => {
    it("returns empty results for no lockfiles", async () => {
      const result = await ScaScanner.scan([]);
      expect(result.dependencies).toHaveLength(0);
      expect(result.findings).toHaveLength(0);
      expect(result.summary.total).toBe(0);
    });

    it("deduplicates dependencies across files", async () => {
      const result = await ScaScanner.scan([
        {
          filename: "package-lock.json",
          content: JSON.stringify({
            packages: {
              "": {},
              "node_modules/lodash": { version: "4.17.21" },
            },
          }),
        },
      ]);
      expect(result.dependencies.length).toBe(1);
    });
  });

  describe("ScaScanner.buildPrComment", () => {
    it("returns empty string for no findings", () => {
      expect(ScaScanner.buildPrComment([], 10)).toBe("");
    });

    it("includes dependency count and severity table", () => {
      const findings = [{
        dependency: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
        vulnId: "GHSA-xxxx",
        aliases: ["CVE-2021-xxxx"],
        summary: "Prototype Pollution",
        severity: "critical" as const,
        fixedVersion: "4.17.21",
      }];
      const comment = ScaScanner.buildPrComment(findings, 50);
      expect(comment).toContain("1 vulnerable");
      expect(comment).toContain("50 total");
      expect(comment).toContain("lodash");
      expect(comment).toContain("GHSA-xxxx");
      expect(comment).toContain("4.17.21");
    });
  });
});
