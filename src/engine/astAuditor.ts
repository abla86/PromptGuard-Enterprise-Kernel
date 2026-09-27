import { ASTNodeInfo, SecurityViolation, ThreatCategory } from '../types';

export class ASTCodeSecurityAuditor {
  public static readonly FORBIDDEN_PYTHON_CALLS = new Set([
    'eval', 'exec', 'compile', '__import__', 'open', 'system', 'popen', 'spawn',
    'getattr', 'setattr', 'delattr', 'globals', 'locals', 'input', 'breakpoint'
  ]);

  public static readonly FORBIDDEN_PYTHON_MODULES = new Set([
    'os', 'sys', 'subprocess', 'socket', 'shutil', 'requests', 'urllib', 'pty',
    'ctypes', 'multiprocessing', 'threading', 'asyncio', 'importlib', 'pickle'
  ]);

  public static readonly DANGEROUS_SQL_PATTERNS = [
    { pattern: /\bDROP\s+TABLE\b/i, label: 'DROP TABLE', rule: 'AST-SQL-001', risk: 0.95 },
    { pattern: /\bTRUNCATE\s+TABLE\b/i, label: 'TRUNCATE TABLE', rule: 'AST-SQL-002', risk: 0.95 },
    { pattern: /\bALTER\s+USER\b/i, label: 'ALTER USER', rule: 'AST-SQL-003', risk: 0.90 },
    { pattern: /\bGRANT\s+ALL\b/i, label: 'GRANT ALL PRIVILEGES', rule: 'AST-SQL-004', risk: 0.90 },
    { pattern: /;\s*SHUTDOWN\b/i, label: 'DATABASE SHUTDOWN', rule: 'AST-SQL-005', risk: 1.0 },
    { pattern: /--\s*$/m, label: 'SQL Comment Injection / Query Truncation', rule: 'AST-SQL-006', risk: 0.75 },
    { pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b/i, label: 'UNION-based SQL Injection', rule: 'AST-SQL-007', risk: 0.85 },
    { pattern: /\bOR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i, label: 'Tautology SQL Bypass (OR 1=1)', rule: 'AST-SQL-008', risk: 0.85 },
  ];

  public static readonly DANGEROUS_BASH_PATTERNS = [
    { pattern: /\brm\s+-(?:r|f|rf|fr)\s+[\/\*]/i, label: 'Destructive recursive filesystem deletion (rm -rf /)', rule: 'AST-BASH-001', risk: 1.0 },
    { pattern: /\|\s*(?:bash|sh|zsh)\b/i, label: 'Piped shell execution (curl | bash)', rule: 'AST-BASH-002', risk: 0.95 },
    { pattern: /\bchmod\s+(?:-R\s+)?777\b/i, label: 'Unsafe global permission elevation (chmod 777)', rule: 'AST-BASH-003', risk: 0.85 },
    { pattern: /\b(?:mkfifo|nc\s+-e|ncat\s+-e)\b/i, label: 'Reverse shell invocation', rule: 'AST-BASH-004', risk: 1.0 },
    { pattern: /\/etc\/(?:passwd|shadow)\b/i, label: 'Sensitive credential file access', rule: 'AST-BASH-005', risk: 0.90 },
  ];

  /**
   * Static analysis of Python code strings for calls, imports, and AST structure
   */
  public static auditPythonSnippet(codeStr: string): {
    violations: SecurityViolation[];
    astNodes: ASTNodeInfo[];
  } {
    const violations: SecurityViolation[] = [];
    const astNodes: ASTNodeInfo[] = [];

    // Parse imports (e.g., "import os", "import subprocess as sp", "from os import system")
    const importRegex = /(?:import\s+([a-zA-Z0-9_,\s]+)|from\s+([a-zA-Z0-9_]+)\s+import\s+([a-zA-Z0-9_,\s*]+))/g;
    let match: RegExpExecArray | null;

    while ((match = importRegex.exec(codeStr)) !== null) {
      if (match[1]) {
        // Direct import: import os, sys
        const modules = match[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0].trim());
        for (const mod of modules) {
          const isForbidden = this.FORBIDDEN_PYTHON_MODULES.has(mod);
          astNodes.push({
            type: 'ImportNode',
            name: `import ${mod}`,
            isDangerous: isForbidden,
            reason: isForbidden ? `Forbidden system module '${mod}'` : undefined,
          });

          if (isForbidden) {
            violations.push({
              category: ThreatCategory.UNSAFE_CODE_EXECUTION,
              rule_id: 'AST-PY-002',
              risk_score: 1.0,
              description: `Import of forbidden dangerous system module '${mod}'.`,
              extracted_sample: `import ${mod}`,
              layer: 4,
            });
          }
        }
      } else if (match[2]) {
        // from ... import ...
        const fromMod = match[2].trim();
        const importedSymbols = match[3].split(',').map((s) => s.trim().split(/\s+as\s+/)[0].trim());
        const isModForbidden = this.FORBIDDEN_PYTHON_MODULES.has(fromMod);

        astNodes.push({
          type: 'ImportFromNode',
          name: `from ${fromMod} import ${match[3]}`,
          isDangerous: isModForbidden,
          reason: isModForbidden ? `Importing from forbidden system module '${fromMod}'` : undefined,
        });

        if (isModForbidden) {
          violations.push({
            category: ThreatCategory.UNSAFE_CODE_EXECUTION,
            rule_id: 'AST-PY-002',
            risk_score: 1.0,
            description: `Import from forbidden system module '${fromMod}'.`,
            extracted_sample: `from ${fromMod} import ${match[3]}`,
            layer: 4,
          });
        }

        for (const sym of importedSymbols) {
          if (this.FORBIDDEN_PYTHON_CALLS.has(sym)) {
            violations.push({
              category: ThreatCategory.UNSAFE_CODE_EXECUTION,
              rule_id: 'AST-PY-001',
              risk_score: 1.0,
              description: `Imported forbidden executable call '${sym}'.`,
              extracted_sample: `from ${fromMod} import ${sym}`,
              layer: 4,
            });
          }
        }
      }
    }

    // Function calls detection (e.g., eval(), os.system(), subprocess.Popen())
    const callRegex = /\b([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_]+))?\s*\(/g;
    while ((match = callRegex.exec(codeStr)) !== null) {
      const parentObj = match[2] ? match[1] : '';
      const funcName = match[2] || match[1];
      const fullName = match[2] ? `${parentObj}.${funcName}` : funcName;

      const isCallForbidden = this.FORBIDDEN_PYTHON_CALLS.has(funcName) || this.FORBIDDEN_PYTHON_CALLS.has(fullName);
      const isParentDangerous = parentObj && this.FORBIDDEN_PYTHON_MODULES.has(parentObj);

      if (isCallForbidden || isParentDangerous) {
        astNodes.push({
          type: 'CallNode',
          name: `${fullName}()`,
          isDangerous: true,
          reason: `Forbidden system invocation: ${fullName}()`,
        });

        violations.push({
          category: ThreatCategory.UNSAFE_CODE_EXECUTION,
          rule_id: 'AST-PY-001',
          risk_score: 1.0,
          description: `Unauthorized runtime system execution call '${fullName}()' detected.`,
          extracted_sample: `${fullName}()`,
          layer: 4,
        });
      } else {
        astNodes.push({
          type: 'CallNode',
          name: `${fullName}()`,
          isDangerous: false,
        });
      }
    }

    return { violations, astNodes };
  }

  /**
   * Static analysis of SQL queries
   */
  public static auditSqlSnippet(sqlStr: string): {
    violations: SecurityViolation[];
    astNodes: ASTNodeInfo[];
  } {
    const violations: SecurityViolation[] = [];
    const astNodes: ASTNodeInfo[] = [];

    for (const item of this.DANGEROUS_SQL_PATTERNS) {
      const match = sqlStr.match(item.pattern);
      if (match) {
        astNodes.push({
          type: 'SqlStatementNode',
          name: item.label,
          isDangerous: true,
          reason: item.label,
        });

        violations.push({
          category: ThreatCategory.UNSAFE_CODE_EXECUTION,
          rule_id: item.rule,
          risk_score: item.risk,
          description: `Destructive or unauthorized SQL statement detected: ${item.label}.`,
          extracted_sample: match[0],
          layer: 4,
        });
      }
    }

    return { violations, astNodes };
  }

  /**
   * Static analysis of Bash / Shell scripts
   */
  public static auditBashSnippet(bashStr: string): {
    violations: SecurityViolation[];
    astNodes: ASTNodeInfo[];
  } {
    const violations: SecurityViolation[] = [];
    const astNodes: ASTNodeInfo[] = [];

    for (const item of this.DANGEROUS_BASH_PATTERNS) {
      const match = bashStr.match(item.pattern);
      if (match) {
        astNodes.push({
          type: 'BashExecNode',
          name: item.label,
          isDangerous: true,
          reason: item.label,
        });

        violations.push({
          category: ThreatCategory.UNSAFE_CODE_EXECUTION,
          rule_id: item.rule,
          risk_score: item.risk,
          description: `Forbidden shell command pattern detected: ${item.label}.`,
          extracted_sample: match[0],
          layer: 4,
        });
      }
    }

    return { violations, astNodes };
  }
}
