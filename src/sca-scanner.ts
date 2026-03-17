import * as core from "@actions/core";
import axios from "axios";

export interface ScaDependency {
  name: string;
  version: string;
  ecosystem: string;
}

export interface ScaFinding {
  dependency: ScaDependency;
  vulnId: string;
  aliases: string[];
  summary: string;
  severity: "critical" | "high" | "medium" | "low";
  score?: number;
  fixedVersion?: string;
}

const LOCKFILE_MAP: Record<string, string> = {
  "package-lock.json": "npm",
  "yarn.lock": "npm",
  "pnpm-lock.yaml": "npm",
  "Pipfile.lock": "PyPI",
  "requirements.txt": "PyPI",
  "poetry.lock": "PyPI",
  "go.sum": "Go",
  "go.mod": "Go",
  "Gemfile.lock": "RubyGems",
  "composer.lock": "Packagist",
  "Cargo.lock": "crates.io",
};

export function isLockfile(filename: string): boolean {
  const basename = filename.split("/").pop() || "";
  return basename in LOCKFILE_MAP;
}

export function getEcosystem(filename: string): string | null {
  const basename = filename.split("/").pop() || "";
  return LOCKFILE_MAP[basename] || null;
}

function parsePackageLockJson(content: string): ScaDependency[] {
  try {
    const pkg = JSON.parse(content);
    const deps: ScaDependency[] = [];
    // v2/v3 format (packages)
    if (pkg.packages) {
      for (const [path, info] of Object.entries(pkg.packages) as any) {
        if (path === "") continue; // root package
        const name = path.replace(/^node_modules\//, "");
        if (info.version) {
          deps.push({ name, version: info.version, ecosystem: "npm" });
        }
      }
    }
    // v1 format (dependencies)
    else if (pkg.dependencies) {
      for (const [name, info] of Object.entries(pkg.dependencies) as any) {
        if (info.version) {
          deps.push({ name, version: info.version, ecosystem: "npm" });
        }
      }
    }
    return deps;
  } catch { return []; }
}

function parseYarnLock(content: string): ScaDependency[] {
  const deps: ScaDependency[] = [];
  const regex = /^"?(@?[^@\s]+)@[^"]*"?:\s*\n\s+version\s+"([^"]+)"/gm;
  let match;
  while ((match = regex.exec(content)) !== null) {
    deps.push({ name: match[1], version: match[2], ecosystem: "npm" });
  }
  return deps;
}

function parseRequirementsTxt(content: string): ScaDependency[] {
  const deps: ScaDependency[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)==([^\s;#]+)/);
    if (match) {
      deps.push({ name: match[1], version: match[2], ecosystem: "PyPI" });
    }
  }
  return deps;
}

function parseGoSum(content: string): ScaDependency[] {
  const deps: ScaDependency[] = [];
  const seen = new Set<string>();
  for (const line of content.split("\n")) {
    const match = line.match(/^(\S+)\s+v([^\s/]+)/);
    if (match) {
      const key = `${match[1]}@${match[2]}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({ name: match[1], version: match[2], ecosystem: "Go" });
      }
    }
  }
  return deps;
}

function parseGemfileLock(content: string): ScaDependency[] {
  const deps: ScaDependency[] = [];
  const specsSection = content.match(/specs:\n([\s\S]*?)(?:\n\n|\nPLATFORMS)/);
  if (specsSection) {
    const regex = /^\s{4}(\S+)\s+\(([^)]+)\)/gm;
    let match;
    while ((match = regex.exec(specsSection[1])) !== null) {
      deps.push({ name: match[1], version: match[2], ecosystem: "RubyGems" });
    }
  }
  return deps;
}

function parseCargoLock(content: string): ScaDependency[] {
  const deps: ScaDependency[] = [];
  const regex = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    deps.push({ name: match[1], version: match[2], ecosystem: "crates.io" });
  }
  return deps;
}

function parseComposerLock(content: string): ScaDependency[] {
  try {
    const pkg = JSON.parse(content);
    return (pkg.packages || []).map((p: any) => ({
      name: p.name,
      version: (p.version || "").replace(/^v/, ""),
      ecosystem: "Packagist",
    }));
  } catch { return []; }
}

export function parseLockfile(filename: string, content: string): ScaDependency[] {
  const basename = filename.split("/").pop() || "";
  switch (basename) {
    case "package-lock.json": return parsePackageLockJson(content);
    case "yarn.lock": return parseYarnLock(content);
    case "requirements.txt": return parseRequirementsTxt(content);
    case "go.sum":
    case "go.mod": return parseGoSum(content);
    case "Gemfile.lock": return parseGemfileLock(content);
    case "Cargo.lock": return parseCargoLock(content);
    case "composer.lock": return parseComposerLock(content);
    case "Pipfile.lock":
      try {
        const pipfile = JSON.parse(content);
        return Object.entries(pipfile.default || {}).map(([name, info]: any) => ({
          name,
          version: (info.version || "").replace(/^==/, ""),
          ecosystem: "PyPI",
        }));
      } catch { return []; }
    default: return [];
  }
}

async function queryOsvBatch(deps: ScaDependency[]): Promise<Map<string, ScaFinding[]>> {
  const results = new Map<string, ScaFinding[]>();
  if (deps.length === 0) return results;

  const queries = deps.map(d => ({
    package: { name: d.name, ecosystem: d.ecosystem },
    version: d.version,
  }));

  try {
    const response = await axios.post("https://api.osv.dev/v1/querybatch", { queries }, { timeout: 30000 });
    const batchResults = response.data.results || [];

    for (let i = 0; i < batchResults.length; i++) {
      const dep = deps[i];
      const vulns = batchResults[i].vulns || [];
      if (vulns.length > 0) {
        const findings: ScaFinding[] = vulns.map((v: any) => {
          let severity: "critical" | "high" | "medium" | "low" = "medium";
          let score: number | undefined;
          for (const sev of v.severity || []) {
            if (sev.type === "CVSS_V3") {
              score = parseFloat(sev.score);
              if (score >= 9.0) severity = "critical";
              else if (score >= 7.0) severity = "high";
              else if (score >= 4.0) severity = "medium";
              else severity = "low";
            }
          }
          let fixedVersion: string | undefined;
          for (const aff of v.affected || []) {
            for (const range of aff.ranges || []) {
              for (const event of range.events || []) {
                if (event.fixed) fixedVersion = event.fixed;
              }
            }
          }
          return {
            dependency: dep,
            vulnId: v.id,
            aliases: v.aliases || [],
            summary: v.summary || v.id,
            severity,
            score,
            fixedVersion,
          };
        });
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        results.set(key, findings);
      }
    }
  } catch (err: any) {
    core.warning(`OSV.dev query failed: ${err.message}. Skipping SCA vulnerability check.`);
  }

  return results;
}

export class ScaScanner {
  static async scan(files: { filename: string; content: string }[]): Promise<{
    dependencies: ScaDependency[];
    findings: ScaFinding[];
    summary: { total: number; vulnerable: number; critical: number; high: number; medium: number; low: number };
  }> {
    // 1. Parse all lockfiles
    const allDeps: ScaDependency[] = [];
    const seen = new Set<string>();
    for (const file of files) {
      const deps = parseLockfile(file.filename, file.content);
      for (const dep of deps) {
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          allDeps.push(dep);
        }
      }
    }

    core.info(`Parsed ${allDeps.length} dependencies from ${files.length} lockfile(s)`);

    if (allDeps.length === 0) {
      return {
        dependencies: [],
        findings: [],
        summary: { total: 0, vulnerable: 0, critical: 0, high: 0, medium: 0, low: 0 },
      };
    }

    // 2. Query OSV.dev
    const osvResults = await queryOsvBatch(allDeps);

    // 3. Flatten findings
    const allFindings: ScaFinding[] = [];
    for (const findings of osvResults.values()) {
      allFindings.push(...findings);
    }

    // Sort by severity
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => order[a.severity] - order[b.severity]);

    return {
      dependencies: allDeps,
      findings: allFindings,
      summary: {
        total: allDeps.length,
        vulnerable: osvResults.size,
        critical: allFindings.filter(f => f.severity === "critical").length,
        high: allFindings.filter(f => f.severity === "high").length,
        medium: allFindings.filter(f => f.severity === "medium").length,
        low: allFindings.filter(f => f.severity === "low").length,
      },
    };
  }

  static buildPrComment(findings: ScaFinding[], totalDeps: number): string {
    if (findings.length === 0) return "";

    const lines: string[] = [];
    lines.push("## 📦 Fortly Dependency Scan\n");
    lines.push(`**${findings.length} vulnerable dependenc${findings.length === 1 ? "y" : "ies"}** out of ${totalDeps} total\n`);

    const critical = findings.filter(f => f.severity === "critical").length;
    const high = findings.filter(f => f.severity === "high").length;

    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    if (critical > 0) lines.push(`| 🔴 Critical | ${critical} |`);
    if (high > 0) lines.push(`| 🟠 High | ${high} |`);
    const medium = findings.filter(f => f.severity === "medium").length;
    const low = findings.filter(f => f.severity === "low").length;
    if (medium > 0) lines.push(`| 🟡 Medium | ${medium} |`);
    if (low > 0) lines.push(`| 🟢 Low | ${low} |`);
    lines.push("");

    lines.push("### Vulnerable Dependencies\n");
    lines.push("| Package | Version | Vulnerability | Severity | Fix |");
    lines.push("|---------|---------|---------------|----------|-----|");

    for (const f of findings.slice(0, 25)) {
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : "🟢";
      const fix = f.fixedVersion ? `\`${f.fixedVersion}\`` : "No fix";
      lines.push(`| \`${f.dependency.name}\` | \`${f.dependency.version}\` | ${f.vulnId} | ${icon} ${f.severity} | ${fix} |`);
    }
    if (findings.length > 25) lines.push(`\n_...and ${findings.length - 25} more_`);

    lines.push("\n---");
    lines.push("*📦 Scanned by [Fortly](https://fortly.io) — Dependency Security*");

    return lines.join("\n");
  }
}
