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
