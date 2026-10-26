# PromptGuard Enterprise Kernel

Bounded prompt/tool security demonstration implementing trust-aware inspection, taint tracking, test vectors and auditable security decisions.

## Engineering evidence

- React + TypeScript + Vite
- Component-based application architecture
- Explicit service boundaries
- Local, inspectable state and diagnostics workflows
- Automated TypeScript verification
- Production build verification
- Security-conscious operational boundaries

## Scope

This is a security engineering demonstration. It does not claim to detect every prompt injection, malicious payload or tool-abuse scenario. Results must be treated as bounded demonstrations rather than a universal security guarantee.

## Local development

Requirements:

- Node.js 20+
- npm

Install dependencies:

```bash
npm install
```

Start development with:

```bash
npm run dev
```

## Verification

```bash
npm install
npm run lint
npm run build
```

The CI workflow runs the same checks that do not require external credentials or a live production environment.

## Security and secrets

Never commit API keys, tokens, passwords, Home Assistant credentials, private configuration or personal data. Use the supplied environment-example files where applicable.

## Publication boundary

The repository is published as a technical portfolio demonstration. Configuration files and simulated data are not evidence that a real external Home Assistant system, production security boundary or production deployment has been verified.

## License

Apache License 2.0. See [LICENSE](LICENSE).


## Disclaimers and limitations

- **Project status:** Features may be incomplete, experimental, or unverified. Confirm behavior against the current code, tests, and configuration before relying on it.
- **No warranty:** Provided as-is, without guarantees of correctness, availability, security, or production readiness. Review and test changes before production use.
- **Security and data:** Never commit credentials, API keys, personal information, or confidential data. Review permissions, external services, logging, retention, and dependency risks. Automated checks are not a complete security audit.
- **Testing and deployment:** Passing tests or static checks does not prove all behavior is correct or deployment is safe. Verify functionality, access controls, dependencies, backups, monitoring, and operational requirements independently.
- **Domain-specific limitation:** Prompt-injection detection and policy checks are defense-in-depth aids, not guarantees. Validate with representative adversarial tests, monitor false positives and false negatives, and never rely on a single detector as the only security boundary.
