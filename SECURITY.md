# Security Policy

## Scope and limitations
PromptGuard is a bounded prompt/tool-security demonstration, not a universal prompt-injection detector or a production security boundary. A clean scan does not prove that a prompt, model, tool, workflow or deployment is safe. Findings require human validation.

## Safe operation
- Test only systems and data you own or are explicitly authorized to assess.
- Treat prompts, retrieved documents, model output and tool output as untrusted.
- Do not connect demonstration controls to privileged production tools without a separate threat model, authorization checks, logging and negative tests.
- Do not commit credentials, API keys, tokens, personal data or confidential prompts.

## Reporting
Report suspected vulnerabilities privately through GitHub private vulnerability reporting when available. Otherwise contact the maintainer privately before public disclosure. Include the affected commit, reproduction steps and impact; redact secrets and personal data.

## Verification boundary
Build and TypeScript checks are not a complete penetration test, runtime test or proof of resistance to prompt injection.