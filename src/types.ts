export enum TrustLevel {
  TRUSTED_SYSTEM = 0,
  AUTHENTICATED_USER = 1,
  UNTRUSTED_EXTERNAL = 2, // e.g. web-scrapes, emails, PDFs, external API payloads
}

export enum ThreatCategory {
  HOMOGLYPH_OBFUSCATION = 'HOMOGLYPH_OBFUSCATION',
  INDIRECT_ROLE_HIJACK = 'INDIRECT_ROLE_HIJACK',
  SPECIAL_TOKEN_INJECTION = 'SPECIAL_TOKEN_INJECTION',
  MARKDOWN_EXFILTRATION = 'MARKDOWN_EXFILTRATION',
  RECURSIVE_ENCODING_BYPASS = 'RECURSIVE_ENCODING_BYPASS',
  UNSAFE_CODE_EXECUTION = 'UNSAFE_CODE_EXECUTION',
  TAINT_POLICY_VIOLATION = 'TAINT_POLICY_VIOLATION',
  ZERO_WIDTH_SMUGGLING = 'ZERO_WIDTH_SMUGGLING',
}

export enum EnforcementAction {
  ALLOW = 'ALLOW',
  SANITIZE_AND_WRAP = 'SANITIZE_AND_WRAP',
  BLOCK = 'BLOCK',
}

export enum ToolPrivilegeLevel {
  READ_ONLY = 'READ_ONLY',
  ELEVATED_WRITE = 'ELEVATED_WRITE',
  DESTRUCTIVE_ADMIN = 'DESTRUCTIVE_ADMIN',
  EXTERNAL_NETWORK = 'EXTERNAL_NETWORK',
}

export interface SecurityViolation {
  category: ThreatCategory;
  rule_id: string;
  risk_score: number;
  description: string;
  extracted_sample: string;
  layer?: number;
}

export interface DecodedLayer {
  layer_type: string;
  depth: number;
  content: string;
}

export interface HomoglyphMatch {
  char: string;
  replacement: string;
  index: number;
  originalCode: string;
}

export interface ZeroWidthMatch {
  char: string;
  codePoint: string;
  name: string;
  index: number;
}

export interface ASTNodeInfo {
  type: string;
  name: string;
  isDangerous: boolean;
  reason?: string;
  line?: number;
}

export interface TaintContainer {
  original_text: string;
  normalized_text: string;
  trust_level: TrustLevel;
  boundary_token: string;
  action: EnforcementAction;
  max_risk: floatNumber;
  violations: SecurityViolation[];
  processingTimeMs: number;
  layersInfo: {
    hadZeroWidth: boolean;
    zeroWidthMatches: ZeroWidthMatch[];
    hadHomoglyphs: boolean;
    homoglyphMatches: HomoglyphMatch[];
    decodedLayers: DecodedLayer[];
    astNodes: ASTNodeInfo[];
    cleanNormalized: string;
  };
}

export type floatNumber = number;

export interface ToolDefinition {
  id: string;
  name: string;
  description: string;
  privilege: ToolPrivilegeLevel;
  requiresExplicitUserConfirmation: boolean;
  category: 'database' | 'system' | 'network' | 'search' | 'messaging';
}

export interface TestVector {
  id: string;
  name: string;
  description: string;
  trust: TrustLevel;
  payload: string;
  expect_block: boolean;
  targetTool?: string;
  category: string;
}

export interface TestResult {
  test: TestVector;
  result: TaintContainer;
  passed: boolean;
  durationMs: number;
}

export interface EngineConfig {
  blockRiskThreshold: number;
  sanitizeRiskThreshold: number;
  enableHomoglyphNorm: boolean;
  enableEvilUnicodeStrip: boolean;
  enableRecursiveDecode: boolean;
  maxDecodeDepth: number;
  enableDelimiterScan: boolean;
  enableRoleOverrideScan: boolean;
  enableExfiltrationScan: boolean;
  enableAstAudit: boolean;
  strictTaintPolicy: boolean;
}
