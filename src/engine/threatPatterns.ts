export class ThreatPatterns {
  // Structural Escape Tokens & LLM Internal Delimiters
  public static readonly DELIMITER_TOKENS: { pattern: RegExp; name: string; family: string }[] = [
    // ChatML Family
    { pattern: /<\|im_start\|>/gi, name: '<|im_start|>', family: 'ChatML' },
    { pattern: /<\|im_end\|>/gi, name: '<|im_end|>', family: 'ChatML' },
    { pattern: /<\|endoftext\|>/gi, name: '<|endoftext|>', family: 'GPT / OpenAI' },
    // LLaMA / Mistral Family
    { pattern: /\[INST\]/gi, name: '[INST]', family: 'LLaMA / Mistral' },
    { pattern: /\[\/INST\]/gi, name: '[/INST]', family: 'LLaMA / Mistral' },
    { pattern: /<<SYS>>/gi, name: '<<SYS>>', family: 'LLaMA 2 System' },
    { pattern: /<<\/SYS>>/gi, name: '<</SYS>>', family: 'LLaMA 2 System' },
    // Anthropic / Claude Delimiters
    { pattern: /<\|system\|>/gi, name: '<|system|>', family: 'System Delimiter' },
    { pattern: /<\|user\|>/gi, name: '<|user|>', family: 'User Delimiter' },
    { pattern: /<\|assistant\|>/gi, name: '<|assistant|>', family: 'Assistant Delimiter' },
    { pattern: /\n\nHuman:\s*/gi, name: 'Human: prefix', family: 'Anthropic Claude' },
    { pattern: /\n\nAssistant:\s*/gi, name: 'Assistant: prefix', family: 'Anthropic Claude' },
    // Markdown System Tag Masquerading
    { pattern: /```\s*system/gi, name: '```system', family: 'Markdown Fake System' },
    { pattern: /<s>/gi, name: '<s>', family: 'BOS Token' },
    { pattern: /<\/s>/gi, name: '</s>', family: 'EOS Token' },
  ];

  // Instruction Overrides, Jailbreaks & Role Hijacking
  public static readonly ROLE_OVERRIDE: { pattern: RegExp; description: string; ruleId: string }[] = [
    {
      pattern: /(?:ignore\s+all\s+previous\s+instructions|disregard\s+(?:all\s+)?prior\s+rules|forget\s+all\s+previous\s+directives)/i,
      description: 'Direct instruction wipe/override attempt',
      ruleId: 'HIJACK-001',
    },
    {
      pattern: /(?:you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode\s+enabled|jailbroken\s+mode)/i,
      description: 'Developer / DAN mode jailbreak trigger',
      ruleId: 'HIJACK-002',
    },
    {
      pattern: /(?:system\s*override:|emergency\s*protocol\s*alpha:|admin\s*override:)/i,
      description: 'System override protocol masquerade',
      ruleId: 'HIJACK-003',
    },
    {
      pattern: /(?:from\s+now\s+on\s+you\s+act\s+as\s+an?\s+unconstrained|unfiltered\s+mode\s+active)/i,
      description: 'Persona constraint removal attempt',
      ruleId: 'HIJACK-004',
    },
    {
      pattern: /(?:new\s+primary\s+objective:\s*reveal|your\s+true\s+objective\s+is)/i,
      description: 'Primary objective hijacking',
      ruleId: 'HIJACK-005',
    },
    {
      pattern: /(?:repeat\s+the\s+above\s+system\s+prompt|dump\s+your\s+system\s+instructions|print\s+initial\s+prompt)/i,
      description: 'System prompt extraction attempt',
      ruleId: 'HIJACK-006',
    },
  ];

  // Markdown & Webhook Exfiltration patterns
  public static readonly EXFILTRATION: { pattern: RegExp; description: string; ruleId: string }[] = [
    {
      pattern: /!\[.*?\]\(https?:\/\/[^\s\)]+[\?&](?:data|token|leak|secret|exfil|key|pwd|session)=.*?[\)\s]/i,
      description: 'Markdown image stealth webhook exfiltration',
      ruleId: 'EXFIL-001',
    },
    {
      pattern: /<img\s+[^>]*src=['"]https?:\/\/[^'"]+[\?&](?:data|token|key|pwd|secret|auth)=[^'"]*['"]/i,
      description: 'HTML image tag data leak attempt',
      ruleId: 'EXFIL-002',
    },
    {
      pattern: /(?:curl|fetch|wget)\s+-[sS]*L?\s+https?:\/\/[^\s]+/i,
      description: 'Out-of-band network exfiltration command',
      ruleId: 'EXFIL-003',
    },
    {
      pattern: /https?:\/\/[^\s\/]+(?:\.ngrok\.io|\.requestcatcher\.com|\.webhook\.site|\.burpcollaborator\.net|\.interactsh\.com)/i,
      description: 'Known OOB exfiltration receiver endpoint',
      ruleId: 'EXFIL-004',
    },
  ];
}
