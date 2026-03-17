import * as core from "@actions/core";

export interface SastFinding {
  ruleId: string;
  language: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  filename: string;
  lineNumber: number;
  codeSnippet: string;
  cwe?: string;
  fixSuggestion: string;
}

interface SastRule {
  id: string;
  language: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  pattern: RegExp;
  cwe?: string;
  fixSuggestion: string;
  exclusionPattern?: RegExp;
}

const CODE_EXTENSIONS: Record<string, string> = {
  ".ts": "javascript", ".tsx": "javascript", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
  ".py": "python", ".pyw": "python",
  ".java": "java",
  ".go": "go",
};

function getLanguage(filename: string): string | null {
  for (const [ext, lang] of Object.entries(CODE_EXTENSIONS)) {
    if (filename.endsWith(ext)) return lang;
  }
  return null;
}

// Embed top rules per language (subset of the full backend ruleset for speed)
const RULES: SastRule[] = [
  // JavaScript/TypeScript (top 15)
  { id: "js-eval", language: "javascript", severity: "critical", title: "Use of eval()", pattern: /\beval\s*\(/g, cwe: "CWE-95", fixSuggestion: "Use JSON.parse() or a sandboxed environment" },
  { id: "js-innerhtml", language: "javascript", severity: "high", title: "Direct innerHTML assignment", pattern: /\.innerHTML\s*=(?!=)/g, cwe: "CWE-79", fixSuggestion: "Use textContent or DOMPurify" },
  { id: "js-document-write", language: "javascript", severity: "high", title: "document.write() usage", pattern: /document\.write\s*\(/g, cwe: "CWE-79", fixSuggestion: "Use DOM APIs instead" },
  { id: "js-dangerously-set-html", language: "javascript", severity: "high", title: "React dangerouslySetInnerHTML", pattern: /dangerouslySetInnerHTML/g, cwe: "CWE-79", fixSuggestion: "Sanitize with DOMPurify" },
  { id: "js-exec-sync", language: "javascript", severity: "critical", title: "Shell command execution", pattern: /(?:execSync|exec)\s*\(\s*[`'"]/g, cwe: "CWE-78", fixSuggestion: "Use execFile/spawn with array arguments" },
  { id: "js-sql-template", language: "javascript", severity: "critical", title: "SQL in template literal", pattern: /(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/gi, cwe: "CWE-89", fixSuggestion: "Use parameterized queries" },
  { id: "js-sql-concat", language: "javascript", severity: "critical", title: "SQL string concatenation", pattern: /(?:query|execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+/gi, cwe: "CWE-89", fixSuggestion: "Use parameterized queries" },
  { id: "js-tls-disabled", language: "javascript", severity: "high", title: "TLS verification disabled", pattern: /rejectUnauthorized\s*:\s*false/g, cwe: "CWE-295", fixSuggestion: "Enable TLS verification" },
  { id: "js-cors-wildcard", language: "javascript", severity: "medium", title: "CORS wildcard origin", pattern: /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/g, cwe: "CWE-942", fixSuggestion: "Restrict to specific origins" },
  { id: "js-md5", language: "javascript", severity: "medium", title: "MD5 hash usage", pattern: /createHash\s*\(\s*['"]md5['"]\)/g, cwe: "CWE-328", fixSuggestion: "Use SHA-256" },
  { id: "js-prototype-pollution", language: "javascript", severity: "high", title: "Prototype pollution risk", pattern: /\[(?:key|prop|name|field)\]\s*=/g, cwe: "CWE-1321", fixSuggestion: "Validate keys against __proto__, constructor" },
  { id: "js-ssrf", language: "javascript", severity: "high", title: "Potential SSRF", pattern: /(?:axios|fetch|http\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.)/g, cwe: "CWE-918", fixSuggestion: "Validate URLs, block internal IPs" },

  // Python (top 12)
  { id: "py-eval", language: "python", severity: "critical", title: "Use of eval()", pattern: /\beval\s*\(/g, cwe: "CWE-95", fixSuggestion: "Use ast.literal_eval()" },
  { id: "py-exec", language: "python", severity: "critical", title: "Use of exec()", pattern: /\bexec\s*\(/g, cwe: "CWE-95", fixSuggestion: "Avoid dynamic code execution" },
  { id: "py-os-system", language: "python", severity: "critical", title: "os.system() command execution", pattern: /os\.system\s*\(/g, cwe: "CWE-78", fixSuggestion: "Use subprocess.run(shell=False)" },
  { id: "py-subprocess-shell", language: "python", severity: "critical", title: "subprocess with shell=True", pattern: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/g, cwe: "CWE-78", fixSuggestion: "Set shell=False" },
  { id: "py-pickle", language: "python", severity: "critical", title: "pickle deserialization", pattern: /pickle\.loads?\s*\(/g, cwe: "CWE-502", fixSuggestion: "Use JSON" },
  { id: "py-yaml-unsafe", language: "python", severity: "high", title: "yaml.load() without SafeLoader", pattern: /yaml\.load\s*\([^)]*\)/g, cwe: "CWE-502", fixSuggestion: "Use yaml.safe_load()", exclusionPattern: /SafeLoader|safe_load/ },
  { id: "py-sql-format", language: "python", severity: "critical", title: "SQL string formatting", pattern: /(?:execute|cursor)\s*\(\s*(?:f['"]|['"].*%s|['"].*\.format)/g, cwe: "CWE-89", fixSuggestion: "Use parameterized queries" },
  { id: "py-flask-debug", language: "python", severity: "high", title: "Flask debug mode", pattern: /app\.run\s*\([^)]*debug\s*=\s*True/g, cwe: "CWE-489", fixSuggestion: "Disable in production" },
  { id: "py-ssl-disabled", language: "python", severity: "high", title: "SSL verification disabled", pattern: /verify\s*=\s*False/g, cwe: "CWE-295", fixSuggestion: "Enable SSL verification" },
  { id: "py-md5", language: "python", severity: "medium", title: "MD5 hash usage", pattern: /hashlib\.md5\s*\(/g, cwe: "CWE-328", fixSuggestion: "Use hashlib.sha256()" },

  // Java (top 10)
  { id: "java-sql-concat", language: "java", severity: "critical", title: "SQL concatenation", pattern: /(?:executeQuery|prepareStatement)\s*\(\s*['"][^'"]*['"]\s*\+/g, cwe: "CWE-89", fixSuggestion: "Use PreparedStatement" },
  { id: "java-runtime-exec", language: "java", severity: "critical", title: "Runtime.exec()", pattern: /Runtime\.getRuntime\s*\(\s*\)\.exec/g, cwe: "CWE-78", fixSuggestion: "Use ProcessBuilder" },
  { id: "java-xxe", language: "java", severity: "critical", title: "XXE vulnerable parser", pattern: /DocumentBuilderFactory\.newInstance\s*\(/g, cwe: "CWE-611", fixSuggestion: "Disable external entities" },
  { id: "java-deserialization", language: "java", severity: "critical", title: "Unsafe deserialization", pattern: /ObjectInputStream\s*\(/g, cwe: "CWE-502", fixSuggestion: "Use allowlisting filter" },
  { id: "java-weak-random", language: "java", severity: "medium", title: "Weak random", pattern: /new\s+Random\s*\(/g, cwe: "CWE-330", fixSuggestion: "Use SecureRandom" },
  { id: "java-ecb-mode", language: "java", severity: "high", title: "ECB cipher mode", pattern: /Cipher\.getInstance\s*\(\s*['"]AES\/ECB/g, cwe: "CWE-327", fixSuggestion: "Use AES/GCM" },
  { id: "java-tls-disabled", language: "java", severity: "high", title: "TLS disabled", pattern: /TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER/g, cwe: "CWE-295", fixSuggestion: "Use proper TLS" },

  // Go (top 8)
  { id: "go-sql-concat", language: "go", severity: "critical", title: "SQL concatenation", pattern: /\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+)/g, cwe: "CWE-89", fixSuggestion: "Use parameterized queries" },
  { id: "go-exec-command", language: "go", severity: "critical", title: "exec.Command with user input", pattern: /exec\.Command\s*\(\s*(?:r\.|req\.|input|userInput)/g, cwe: "CWE-78", fixSuggestion: "Validate command arguments" },
  { id: "go-template-html", language: "go", severity: "high", title: "template.HTML (unescaped)", pattern: /template\.HTML\s*\(/g, cwe: "CWE-79", fixSuggestion: "Use auto-escaping templates" },
  { id: "go-tls-skip-verify", language: "go", severity: "high", title: "TLS verification disabled", pattern: /InsecureSkipVerify\s*:\s*true/g, cwe: "CWE-295", fixSuggestion: "Enable TLS verification" },
  { id: "go-weak-rand", language: "go", severity: "medium", title: "math/rand for security", pattern: /rand\.(?:Intn|Int|Float)/g, cwe: "CWE-330", fixSuggestion: "Use crypto/rand" },
  { id: "go-ssrf", language: "go", severity: "high", title: "Potential SSRF", pattern: /http\.(?:Get|Post)\s*\(\s*(?:r\.|req\.|userInput)/g, cwe: "CWE-918", fixSuggestion: "Validate URLs" },
];

const SKIP_PATTERNS = [/node_modules\//, /vendor\//, /\.test\.|\.spec\.|_test\.go$|Test\.java$/, /\.min\.js$/, /dist\//, /build\//];

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split("\n").length;
}

function getSnippet(content: string, lineNum: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNum - 2);
  const end = Math.min(lines.length, lineNum + 1);
  return lines.slice(start, end).join("\n");
}

export class SastScanner {
  static scan(files: { filename: string; content: string }[]): SastFinding[] {
    const findings: SastFinding[] = [];
    const seen = new Set<string>();

    for (const file of files) {
      if (SKIP_PATTERNS.some(p => p.test(file.filename))) continue;

      const language = getLanguage(file.filename);
      if (!language) continue;

      const langRules = RULES.filter(r => r.language === language);

      for (const rule of langRules) {
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = rule.pattern.exec(file.content)) !== null) {
          // Check exclusion
          if (rule.exclusionPattern) {
            const lineStart = file.content.lastIndexOf("\n", match.index) + 1;
            const lineEnd = file.content.indexOf("\n", match.index);
            const fullLine = file.content.substring(lineStart, lineEnd === -1 ? file.content.length : lineEnd);
            if (rule.exclusionPattern.test(fullLine)) continue;
          }

          const lineNumber = getLineNumber(file.content, match.index);
          const dedupeKey = `${rule.id}:${file.filename}:${lineNumber}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);

          findings.push({
            ruleId: rule.id,
            language,
            severity: rule.severity,
            title: rule.title,
            filename: file.filename,
            lineNumber,
            codeSnippet: getSnippet(file.content, lineNumber),
            cwe: rule.cwe,
            fixSuggestion: rule.fixSuggestion,
          });
        }
      }
    }

    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return findings;
  }

  static buildPrComment(findings: SastFinding[]): string {
    if (findings.length === 0) return "";

    const lines: string[] = [];
    lines.push("## 🔍 Fortly Code Security (SAST)\n");
    lines.push(`**${findings.length} issue${findings.length !== 1 ? "s" : ""} found in source code**\n`);

    const critical = findings.filter(f => f.severity === "critical").length;
    const high = findings.filter(f => f.severity === "high").length;
    const medium = findings.filter(f => f.severity === "medium").length;

    lines.push("| Severity | Count |");
    lines.push("|----------|-------|");
    if (critical > 0) lines.push(`| 🔴 Critical | ${critical} |`);
    if (high > 0) lines.push(`| 🟠 High | ${high} |`);
    if (medium > 0) lines.push(`| 🟡 Medium | ${medium} |`);
    lines.push("");

    lines.push("### Findings\n");
    lines.push("| File | Line | Issue | Severity | CWE |");
    lines.push("|------|------|-------|----------|-----|");
    for (const f of findings.slice(0, 25)) {
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : "🟡";
      lines.push(`| \`${f.filename}\` | ${f.lineNumber} | ${f.title} | ${icon} ${f.severity} | ${f.cwe || "-"} |`);
    }
    if (findings.length > 25) lines.push(`\n_...and ${findings.length - 25} more issues_`);

    lines.push("\n---");
    lines.push("*🔍 Scanned by [Fortly](https://fortly.io) — Static Code Analysis*");
    return lines.join("\n");
  }
}
