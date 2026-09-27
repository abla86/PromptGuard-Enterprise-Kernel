import {
  EnforcementAction,
  EngineConfig,
  SecurityViolation,
  TaintContainer,
  ThreatCategory,
  ToolDefinition,
  ToolPrivilegeLevel,
  TrustLevel,
} from '../types';
import { ASTCodeSecurityAuditor } from './astAuditor';
import { AdvancedNormalizer } from './normalizer';
import { ThreatPatterns } from './threatPatterns';

export const DEFAULT_ENGINE_CONFIG: EngineConfig = {
  blockRiskThreshold: 0.85,
  sanitizeRiskThreshold: 0.30,
  enableHomoglyphNorm: true,
  enableEvilUnicodeStrip: true,
  enableRecursiveDecode: true,
  maxDecodeDepth: 3,
  enableDelimiterScan: true,
  enableRoleOverrideScan: true,
  enableExfiltrationScan: true,
  enableAstAudit: true,
  strictTaintPolicy: true,
};

export const AVAILABLE_TOOLS: ToolDefinition[] = [
  {
    id: 'tool_search_db',
    name: 'Vector Database Search',
    description: 'Read-only semantic query against corporate knowledge base',
    privilege: ToolPrivilegeLevel.READ_ONLY,
    requiresExplicitUserConfirmation: false,
    category: 'search',
  },
  {
    id: 'tool_calc',
    name: 'Safe Math Calculator',
    description: 'Deterministic math calculator in sandboxed runtime',
    privilege: ToolPrivilegeLevel.READ_ONLY,
    requiresExplicitUserConfirmation: false,
    category: 'system',
  },
  {
    id: 'tool_execute_sql',
    name: 'Execute SQL Query',
    description: 'Runs dynamic database query against application warehouse',
    privilege: ToolPrivilegeLevel.ELEVATED_WRITE,
    requiresExplicitUserConfirmation: true,
    category: 'database',
  },
  {
    id: 'tool_python_sandbox',
    name: 'Run Python Script',
    description: 'Executes Python snippet in ephemeral execution container',
    privilege: ToolPrivilegeLevel.ELEVATED_WRITE,
    requiresExplicitUserConfirmation: true,
    category: 'system',
  },
  {
    id: 'tool_send_email',
    name: 'Dispatch Outgoing Email',
    description: 'Transmits emails to external stakeholders via SMTP',
    privilege: ToolPrivilegeLevel.EXTERNAL_NETWORK,
    requiresExplicitUserConfirmation: true,
    category: 'messaging',
  },
  {
    id: 'tool_drop_table',
    name: 'Database Schema Admin (DROP/TRUNCATE)',
    description: 'Modifies or drops relational tables',
    privilege: ToolPrivilegeLevel.DESTRUCTIVE_ADMIN,
    requiresExplicitUserConfirmation: true,
    category: 'database',
  },
  {
    id: 'tool_wire_transfer',
    name: 'Initiate Wire Transfer / Payment',
    description: 'Dispatches financial transactions to banking gateway',
    privilege: ToolPrivilegeLevel.DESTRUCTIVE_ADMIN,
    requiresExplicitUserConfirmation: true,
    category: 'network',
  },
];

export class PromptGuardEngine {
  private config: EngineConfig;

  constructor(config: Partial<EngineConfig> = {}) {
    this.config = { ...DEFAULT_ENGINE_CONFIG, ...config };
  }

  public updateConfig(newConfig: Partial<EngineConfig>) {
    this.config = { ...this.config, ...newConfig };
  }

  public getConfig(): EngineConfig {
    return { ...this.config };
  }

  /**
   * Generates a random cryptographic boundary token
   */
  private generateBoundaryToken(): string {
    const arr = new Uint8Array(8);
    crypto.getRandomValues(arr);
    const hex = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return `DATA_CONTAINER_${hex}`;
  }

  /**
   * HTML escape helper
   */
  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Main Kernel Inspection and Taint Containment Pipeline
   */
  public inspectAndContain(
    rawText: string,
    trustLevel: TrustLevel = TrustLevel.UNTRUSTED_EXTERNAL,
    targetToolId?: string
  ): TaintContainer {
    const startTime = performance.now();
    const violations: SecurityViolation[] = [];

    // =========================================================================
    // LAG 1: DE-OBFUSKERING & HOMOGLYPH NORMALISERING
    // =========================================================================
    let workingText = rawText;
    let hadZeroWidth = false;
    let zeroWidthMatches: any[] = [];
    let hadHomoglyphs = false;
    let homoglyphMatches: any[] = [];

    if (this.config.enableEvilUnicodeStrip) {
      const zwResult = AdvancedNormalizer.stripEvilUnicode(workingText);
      workingText = zwResult.cleaned;
      hadZeroWidth = zwResult.hadZeroWidth;
      zeroWidthMatches = zwResult.matches;

      if (hadZeroWidth) {
        violations.push({
          category: ThreatCategory.ZERO_WIDTH_SMUGGLING,
          rule_id: 'NORM-001',
          risk_score: 0.80,
          description: `Invisible Zero-width / BiDi-override control characters stripped (${zeroWidthMatches.length} detected).`,
          extracted_sample: zeroWidthMatches.map((m) => m.name).slice(0, 3).join(', '),
          layer: 1,
        });
      }
    }

    if (this.config.enableHomoglyphNorm) {
      const homoResult = AdvancedNormalizer.normalizeHomoglyphs(workingText);
      workingText = homoResult.normalized;
      hadHomoglyphs = homoResult.hadHomoglyphs;
      homoglyphMatches = homoResult.matches;

      if (hadHomoglyphs) {
        violations.push({
          category: ThreatCategory.HOMOGLYPH_OBFUSCATION,
          rule_id: 'NORM-002',
          risk_score: 0.85,
          description: `Homoglyphs (Cyrillic / Greek) identified and normalized to standard Latin characters (${homoglyphMatches.length} substitutions).`,
          extracted_sample: homoglyphMatches.map((m) => `${m.char} (${m.originalCode}) -> ${m.replacement}`).slice(0, 4).join(', '),
          layer: 1,
        });
      }
    }

    const cleanNormalized = workingText;

    // Recursive multi-step decoding
    let decodedLayers: any[] = [];
    if (this.config.enableRecursiveDecode) {
      decodedLayers = AdvancedNormalizer.recursiveDecode(workingText, this.config.maxDecodeDepth);
      if (decodedLayers.length > 0) {
        violations.push({
          category: ThreatCategory.RECURSIVE_ENCODING_BYPASS,
          rule_id: 'DECODE-001',
          risk_score: 0.90,
          description: `Nested encoded payload unpacked (${decodedLayers.length} layers: ${decodedLayers.map((d) => d.layer_type).join(', ')}).`,
          extracted_sample: decodedLayers[0].content.slice(0, 60),
          layer: 1,
        });
      }
    }

    // Leetspeak normalized pass for rule scanning
    const leetNormalized = AdvancedNormalizer.normalizeLeetspeak(workingText);

    // Prepare all text layers for pattern analysis
    const allLayersToScan: { name: string; text: string }[] = [
      { name: 'Normalized Text', text: workingText },
      { name: 'Leetspeak Scan', text: leetNormalized },
      ...decodedLayers.map((d) => ({ name: `Decoded: ${d.layer_type}`, text: d.content })),
    ];

    // =========================================================================
    // LAG 2: SPESIELLE LLM-DELIMITERE & CHATML TOKEN INJECTION
    // =========================================================================
    if (this.config.enableDelimiterScan) {
      for (const layer of allLayersToScan) {
        for (const tokenDef of ThreatPatterns.DELIMITER_TOKENS) {
          const matches = layer.text.match(tokenDef.pattern);
          if (matches) {
            for (const sample of matches) {
              violations.push({
                category: ThreatCategory.SPECIAL_TOKEN_INJECTION,
                rule_id: 'DELIM-001',
                risk_score: 1.0,
                description: `LLM Delimiter escape token detected [${tokenDef.family}] in layer (${layer.name}).`,
                extracted_sample: sample,
                layer: 2,
              });
            }
          }
        }
      }
    }

    // =========================================================================
    // LAG 3: INSTRUKSJONSOVERSTYRING & EKSFILTRERING
    // =========================================================================
    if (this.config.enableRoleOverrideScan) {
      for (const layer of allLayersToScan) {
        for (const roleDef of ThreatPatterns.ROLE_OVERRIDE) {
          const match = layer.text.match(roleDef.pattern);
          if (match) {
            violations.push({
              category: ThreatCategory.INDIRECT_ROLE_HIJACK,
              rule_id: roleDef.ruleId,
              risk_score: 0.95,
              description: `${roleDef.description} (in layer: ${layer.name}).`,
              extracted_sample: match[0],
              layer: 3,
            });
          }
        }
      }
    }

    if (this.config.enableExfiltrationScan) {
      for (const layer of allLayersToScan) {
        for (const exfilDef of ThreatPatterns.EXFILTRATION) {
          const match = layer.text.match(exfilDef.pattern);
          if (match) {
            violations.push({
              category: ThreatCategory.MARKDOWN_EXFILTRATION,
              rule_id: exfilDef.ruleId,
              risk_score: 0.90,
              description: `${exfilDef.description} (in layer: ${layer.name}).`,
              extracted_sample: match[0].slice(0, 80),
              layer: 3,
            });
          }
        }
      }
    }

    // =========================================================================
    // LAG 4: AST KODESIKRING (Python, SQL, Shell)
    // =========================================================================
    let astNodes: any[] = [];
    if (this.config.enableAstAudit) {
      // Python Audit
      const pyAudit = ASTCodeSecurityAuditor.auditPythonSnippet(workingText);
      violations.push(...pyAudit.violations);
      astNodes.push(...pyAudit.astNodes);

      // SQL Audit
      const sqlAudit = ASTCodeSecurityAuditor.auditSqlSnippet(workingText);
      violations.push(...sqlAudit.violations);
      astNodes.push(...sqlAudit.astNodes);

      // Bash Audit
      const bashAudit = ASTCodeSecurityAuditor.auditBashSnippet(workingText);
      violations.push(...bashAudit.violations);
      astNodes.push(...bashAudit.astNodes);
    }

    // =========================================================================
    // LAG 5: TAINT-SPORING & POLICY ENFORCEMENT
    // =========================================================================
    if (targetToolId && this.config.strictTaintPolicy) {
      const selectedTool = AVAILABLE_TOOLS.find((t) => t.id === targetToolId);
      if (selectedTool) {
        // Enforce taint invariant: UNTRUSTED_EXTERNAL data cannot reach ELEVATED/DESTRUCTIVE tools without validation
        if (
          trustLevel === TrustLevel.UNTRUSTED_EXTERNAL &&
          (selectedTool.privilege === ToolPrivilegeLevel.ELEVATED_WRITE ||
            selectedTool.privilege === ToolPrivilegeLevel.DESTRUCTIVE_ADMIN ||
            selectedTool.privilege === ToolPrivilegeLevel.EXTERNAL_NETWORK)
        ) {
          violations.push({
            category: ThreatCategory.TAINT_POLICY_VIOLATION,
            rule_id: 'TAINT-POLICY-001',
            risk_score: 0.98,
            description: `Taint Policy Violation: UNTRUSTED_EXTERNAL payload cannot be dispatched directly to privileged tool '${selectedTool.name}' (${selectedTool.privilege}) without explicit step-up authentication.`,
            extracted_sample: `Target Tool: ${selectedTool.name} [${selectedTool.privilege}]`,
            layer: 5,
          });
        }
      }
    }

    // Deduplicate violations by rule_id and sample
    const uniqueViolations: SecurityViolation[] = [];
    const seen = new Set<string>();
    for (const v of violations) {
      const key = `${v.rule_id}_${v.extracted_sample}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueViolations.push(v);
      }
    }

    // Evaluate Risk & Action
    const maxRisk = uniqueViolations.length > 0 ? Math.max(...uniqueViolations.map((v) => v.risk_score)) : 0.0;

    let action: EnforcementAction;
    if (maxRisk >= this.config.blockRiskThreshold && trustLevel === TrustLevel.UNTRUSTED_EXTERNAL) {
      action = EnforcementAction.BLOCK;
    } else if (maxRisk >= this.config.sanitizeRiskThreshold || trustLevel === TrustLevel.UNTRUSTED_EXTERNAL) {
      action = EnforcementAction.SANITIZE_AND_WRAP;
    } else {
      action = EnforcementAction.ALLOW;
    }

    // Boundary Token & Taint Envelope
    const boundary = this.generateBoundaryToken();
    const escapedText = this.escapeHtml(cleanNormalized);
    const wrappedPayload = `<${boundary} trust_level="${TrustLevel[trustLevel]}" action="${action}">\n${escapedText}\n</${boundary}>`;

    const endTime = performance.now();

    return {
      original_text: rawText,
      normalized_text: wrappedPayload,
      trust_level: trustLevel,
      boundary_token: boundary,
      action,
      max_risk: Number(maxRisk.toFixed(2)),
      violations: uniqueViolations,
      processingTimeMs: Number((endTime - startTime).toFixed(3)),
      layersInfo: {
        hadZeroWidth,
        zeroWidthMatches,
        hadHomoglyphs,
        homoglyphMatches,
        decodedLayers,
        astNodes,
        cleanNormalized,
      },
    };
  }
}
