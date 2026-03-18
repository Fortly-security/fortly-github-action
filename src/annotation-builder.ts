import { SastFinding } from "./sast-scanner";
import { SecretFinding } from "./secret-scanner";
import { ScaFinding } from "./sca-scanner";

export interface Annotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  message: string;
  title: string;
}

function severityToLevel(severity: string): "notice" | "warning" | "failure" {
  switch (severity) {
    case "critical":
      return "failure";
    case "high":
      return "warning";
    default:
      return "notice";
  }
}

export class AnnotationBuilder {
  static fromSastFindings(findings: SastFinding[]): Annotation[] {
    return findings.map((f) => ({
      path: f.filename,
      start_line: f.lineNumber,
      end_line: f.lineNumber,
      annotation_level: severityToLevel(f.severity),
      message: `${f.title}${f.cwe ? ` (${f.cwe})` : ""}\n\nFix: ${f.fixSuggestion}`,
      title: `SAST: ${f.title}`,
    }));
  }

  static fromSecretFindings(findings: SecretFinding[]): Annotation[] {
    return findings.map((f) => ({
      path: f.filename,
      start_line: f.lineNumber,
      end_line: f.lineNumber,
      annotation_level: severityToLevel(f.severity),
      message: `${f.description} (${f.provider})\n\nRemove this secret and rotate the credential immediately.`,
      title: `Secret: ${f.description}`,
    }));
  }

  static fromScaFindings(
    findings: ScaFinding[],
    lockfileMap: Map<string, string>
  ): Annotation[] {
    return findings.slice(0, 20).map((f) => ({
      path: lockfileMap.get(f.dependency.name) || "package.json",
      start_line: 1,
      end_line: 1,
      annotation_level: severityToLevel(f.severity),
      message: `Vulnerable dependency: ${f.dependency.name}@${f.dependency.version}\n\n${f.summary || f.vulnId}\nFix: upgrade to ${f.fixedVersion || "latest"}`,
      title: `SCA: ${f.dependency.name} — ${f.vulnId}`,
    }));
  }

  /**
   * Merge all annotations, capping at a reasonable limit.
   * GitHub allows up to 50 annotations per API call (batched in status-check).
   */
  static merge(...groups: Annotation[][]): Annotation[] {
    const all: Annotation[] = [];
    for (const group of groups) {
      all.push(...group);
    }
    return all;
  }
}
