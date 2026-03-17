import { SastScanner } from "../sast-scanner";

describe("SastScanner", () => {
  describe("scan", () => {
    // JavaScript/TypeScript
    it("detects eval() in JavaScript", () => {
      const files = [{ filename: "app.js", content: 'const result = eval(userInput);' }];
      const findings = SastScanner.scan(files);
      const f = findings.find(f => f.ruleId === "js-eval");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("critical");
      expect(f!.cwe).toBe("CWE-95");
    });

    it("detects innerHTML assignment", () => {
      const files = [{ filename: "component.tsx", content: 'element.innerHTML = userContent;' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "js-innerhtml")).toBeDefined();
    });

    it("detects dangerouslySetInnerHTML in React", () => {
      const files = [{ filename: "App.tsx", content: '<div dangerouslySetInnerHTML={{__html: data}} />' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "js-dangerously-set-html")).toBeDefined();
    });

    it("detects SQL template literal injection", () => {
      const files = [{ filename: "db.ts", content: 'db.query(`SELECT * FROM users WHERE id = ${userId}`);' }];
      const findings = SastScanner.scan(files);
      const sqlF = findings.find(f => f.ruleId === "js-sql-template");
      expect(sqlF).toBeDefined();
      expect(sqlF!.severity).toBe("critical");
    });

    it("detects SQL string concatenation", () => {
      const files = [{ filename: "db.js", content: 'db.query("SELECT * FROM users WHERE id = " + userId);' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "js-sql-concat")).toBeDefined();
    });

    it("detects TLS verification disabled", () => {
      const files = [{ filename: "api.ts", content: 'const agent = new https.Agent({ rejectUnauthorized: false });' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "js-tls-disabled")).toBeDefined();
    });

    // Python
    it("detects eval() in Python", () => {
      const files = [{ filename: "app.py", content: 'result = eval(user_input)' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "py-eval")).toBeDefined();
    });

    it("detects os.system() in Python", () => {
      const files = [{ filename: "utils.py", content: 'os.system(cmd)' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "py-os-system")).toBeDefined();
    });

    it("detects subprocess shell=True", () => {
      const files = [{ filename: "deploy.py", content: 'subprocess.run(cmd, shell=True)' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "py-subprocess-shell")).toBeDefined();
    });

    it("detects pickle.loads()", () => {
      const files = [{ filename: "data.py", content: 'obj = pickle.loads(data)' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "py-pickle")).toBeDefined();
    });

    // Java
    it("detects SQL concatenation in Java", () => {
      const files = [{ filename: "UserDao.java", content: 'stmt.executeQuery("SELECT * FROM users WHERE id = " + id);' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "java-sql-concat")).toBeDefined();
    });

    it("detects Runtime.exec() in Java", () => {
      const files = [{ filename: "Exec.java", content: 'Runtime.getRuntime().exec(cmd);' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "java-runtime-exec")).toBeDefined();
    });

    it("detects XXE in Java", () => {
      const files = [{ filename: "XmlParser.java", content: 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "java-xxe")).toBeDefined();
    });

    // Go
    it("detects SQL concatenation in Go", () => {
      const files = [{ filename: "db.go", content: 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "go-sql-concat")).toBeDefined();
    });

    it("detects InsecureSkipVerify in Go", () => {
      const files = [{ filename: "client.go", content: 'TLSClientConfig: &tls.Config{InsecureSkipVerify: true}' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "go-tls-skip-verify")).toBeDefined();
    });

    it("detects template.HTML in Go", () => {
      const files = [{ filename: "handler.go", content: 'tmpl.Execute(w, template.HTML(userInput))' }];
      const findings = SastScanner.scan(files);
      expect(findings.find(f => f.ruleId === "go-template-html")).toBeDefined();
    });

    // Filtering
    it("skips test files", () => {
      const files = [{ filename: "app.test.ts", content: 'eval("test")' }];
      const findings = SastScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("skips node_modules", () => {
      const files = [{ filename: "node_modules/lib/index.js", content: 'eval("x")' }];
      const findings = SastScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("skips non-code files", () => {
      const files = [{ filename: "README.md", content: 'eval("x")' }];
      const findings = SastScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("returns empty for clean code", () => {
      const files = [{ filename: "app.ts", content: 'const add = (a: number, b: number) => a + b;' }];
      const findings = SastScanner.scan(files);
      expect(findings).toHaveLength(0);
    });

    it("sorts findings by severity", () => {
      const files = [{
        filename: "app.ts",
        content: 'eval(x);\ncreateHash("md5");\ndocument.write(y);',
      }];
      const findings = SastScanner.scan(files);
      if (findings.length >= 2) {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        for (let i = 1; i < findings.length; i++) {
          expect(order[findings[i].severity]).toBeGreaterThanOrEqual(order[findings[i - 1].severity]);
        }
      }
    });

    it("includes correct line number", () => {
      const files = [{ filename: "app.ts", content: 'const a = 1;\nconst b = 2;\nconst c = eval(x);\n' }];
      const findings = SastScanner.scan(files);
      const f = findings.find(f => f.ruleId === "js-eval");
      expect(f?.lineNumber).toBe(3);
    });

    it("includes code snippet", () => {
      const files = [{ filename: "app.ts", content: 'const a = 1;\nconst b = eval(x);\nconst c = 3;' }];
      const findings = SastScanner.scan(files);
      const f = findings.find(f => f.ruleId === "js-eval");
      expect(f?.codeSnippet).toContain("eval");
    });

    it("detects multiple issues across languages", () => {
      const files = [
        { filename: "app.ts", content: 'eval(x);' },
        { filename: "app.py", content: 'os.system(cmd)' },
        { filename: "App.java", content: 'Runtime.getRuntime().exec(cmd);' },
      ];
      const findings = SastScanner.scan(files);
      const languages = new Set(findings.map(f => f.language));
      expect(languages.size).toBeGreaterThanOrEqual(3);
    });
  });

  describe("buildPrComment", () => {
    it("returns empty string for no findings", () => {
      expect(SastScanner.buildPrComment([])).toBe("");
    });

    it("includes finding count and severity table", () => {
      const findings = [{
        ruleId: "js-eval",
        language: "javascript",
        severity: "critical" as const,
        title: "Use of eval()",
        filename: "app.ts",
        lineNumber: 1,
        codeSnippet: "eval(x)",
        cwe: "CWE-95",
        fixSuggestion: "Use JSON.parse()",
      }];
      const comment = SastScanner.buildPrComment(findings);
      expect(comment).toContain("1 issue");
      expect(comment).toContain("Code Security");
      expect(comment).toContain("CWE-95");
    });
  });
});
