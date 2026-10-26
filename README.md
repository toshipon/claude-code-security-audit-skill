# Claude Code Security Audit Skill

A comprehensive, full-stack security audit skill for [Claude Code](https://claude.ai/code). Run `/security-audit all` and get an end-to-end vulnerability assessment across your entire stack.

## Supported Stack

| Layer | Technology | Standard |
|-------|-----------|----------|
| **Web Application** | Next.js (App Router, Server Actions, Middleware) | OWASP Top 10:2025, WSTG |
| **Infrastructure** | Vercel, Terraform, AWS, GCP, Azure | Vercel Best Practices, CIS Benchmarks |
| **Backend (BaaS)** | Supabase (RLS, Auth, Storage, Edge Functions) | Supabase Hardening Guide |
| **Backend (Python)** | Django, FastAPI, Flask | OWASP + Bandit |
| **Backend (Go)** | Standard library, Gin, Echo | OWASP + govulncheck |
| **Backend (Ruby)** | Ruby on Rails | OWASP + Brakeman |
| **Backend (Rust)** | Actix-web, Axum, Rocket | cargo-audit, unsafe analysis |
| **Mobile (iOS)** | Swift, UIKit/SwiftUI | OWASP MASVS v2 / MASTG |
| **Mobile (Android)** | Kotlin, Java | OWASP MASVS v2 / MASTG |
| **Mobile (Flutter)** | Dart | MASVS + Flutter security patterns |
| **Mobile (React Native)** | JavaScript/TypeScript | MASVS + RN security patterns |
| **Compliance** | PCI-DSS, HIPAA, SOX, GDPR, CCPA, SOC2, ISO27001 | Regulatory standards |
| **Advanced** | Supply Chain, Container/K8s, CI/CD, Secrets, LLM/AI | OWASP Top 10 for LLM, CIS |
| **General Web** | Any web framework | OWASP WSTG |

## Quick Start

### Option 1: Plugin Marketplace (recommended)

Inside Claude Code:

```
/plugin marketplace add toshipon/claude-code-security-audit-skill
/plugin install security-audit@toshipon-security-audit
```

The same thing from a shell:

```bash
claude plugin marketplace add toshipon/claude-code-security-audit-skill
claude plugin install security-audit@toshipon-security-audit
```

The marketplace is named `toshipon-security-audit` (distinct from the companion
[security-assessment](https://github.com/toshipon/claude-code-security-assessment-skill) marketplace `toshipon-security`,
so both can be added side by side).

### Option 2: Plain skill directory (still supported)

The repository root keeps `SKILL.md`, `references/`, and `scripts/` as symlinks into
`plugins/security-audit/skills/security-audit/`, so cloning the whole repository into
`~/.claude/skills/security-audit` still registers `/security-audit`, and existing clones keep working after `git pull`.

```bash
git clone https://github.com/toshipon/claude-code-security-audit-skill.git ~/.claude/skills/security-audit
```

Or as a git submodule:

```bash
cd ~/.claude
git submodule add https://github.com/toshipon/claude-code-security-audit-skill.git skills/security-audit
```

On Windows, git checks out symlinks as plain text files unless `core.symlinks` is enabled, so use
Option 1 there, or clone elsewhere and link only the skill directory:

```bash
git clone https://github.com/toshipon/claude-code-security-audit-skill.git ~/claude-code-security-audit-skill
ln -s ~/claude-code-security-audit-skill/plugins/security-audit/skills/security-audit ~/.claude/skills/security-audit
```

Pick one method. Installing both the plugin and the plain skill registers `/security-audit` twice
(as `security-audit` and `security-audit:security-audit`).

### Usage

```
/security-audit              # Interactive target selection
/security-audit all          # Full-stack audit (recommended)

# Web
/security-audit nextjs       # Next.js only
/security-audit vercel       # Vercel only
/security-audit supabase     # Supabase only
/security-audit web          # Next.js + Vercel + Supabase

# Mobile
/security-audit ios          # iOS only
/security-audit android      # Android only
/security-audit flutter      # Flutter only
/security-audit react-native # React Native only
/security-audit mobile       # All mobile platforms

# Backend
/security-audit python       # Python (Django/FastAPI/Flask)
/security-audit go           # Go
/security-audit rails        # Ruby on Rails
/security-audit rust         # Rust
/security-audit backend      # All backend frameworks

# Infrastructure as Code
/security-audit terraform    # Terraform
/security-audit aws          # AWS
/security-audit gcp          # GCP
/security-audit azure        # Azure
/security-audit iac          # All IaC

# Compliance
/security-audit compliance   # PCI-DSS, HIPAA, SOX, GDPR, CCPA, SOC2, ISO27001

# Advanced Detection
/security-audit supply-chain # Supply chain security
/security-audit container    # Container & Kubernetes
/security-audit cicd         # CI/CD pipeline security
/security-audit secrets      # Secret scanning
/security-audit llm          # LLM/AI security
/security-audit advanced     # All advanced detection
```

## Architecture

```
claude-code-security-audit-skill/
├── .claude-plugin/
│   └── marketplace.json                  # Marketplace manifest (name: toshipon-security-audit)
├── plugins/security-audit/
│   ├── .claude-plugin/
│   │   └── plugin.json                   # Plugin manifest (name: security-audit)
│   └── skills/security-audit/
│       ├── SKILL.md                      # Main skill (loaded into context)
│       ├── scripts/
│       │   └── audit_workflow.py          # Local rules, SARIF import, snapshots, patch validation
│       └── references/                   # Detailed guides (loaded on demand)
│           ├── cvss-scoring.md           # CVSS v4.0 evidence, calculation, and reporting workflow
│           ├── advanced-workflows.md     # Initial v2.0 CLI and remediation workflows
│           ├── nextjs-security.md        # Next.js: Server Actions, Middleware, CSP, CVEs
│           ├── vercel-security.md        # Vercel: CLI checks + Chrome MCP dashboard
│           ├── supabase-security.md      # Supabase: RLS SQL queries + Chrome MCP dashboard
│           ├── web-testing.md            # General web: OWASP WSTG + Top 10:2025
│           ├── ios-testing.md            # iOS: MASVS v2 all 8 categories
│           ├── android-security.md       # Android: MASVS v2 Kotlin/Java
│           ├── flutter-security.md       # Flutter: Dart security patterns
│           ├── react-native-security.md  # React Native: JS/TS + native bridge
│           ├── python-security.md        # Python: Django/FastAPI/Flask + Bandit
│           ├── go-security.md            # Go: goroutine safety, crypto, HTTP
│           ├── rails-security.md         # Rails: Brakeman patterns
│           ├── rust-security.md          # Rust: unsafe, FFI, memory safety
│           ├── terraform-security.md     # Terraform: AWS/GCP/Azure misconfigs
│           ├── aws-security.md           # AWS: CIS Benchmark, Well-Architected
│           ├── gcp-security.md           # GCP: CIS Benchmark, Security Command Center
│           ├── azure-security.md         # Azure: CIS Benchmark, Defender for Cloud
│           ├── compliance-financial.md   # PCI-DSS v4.0, HIPAA, SOX
│           ├── compliance-privacy.md     # GDPR, CCPA, SOC 2, ISO 27001
│           ├── supply-chain-security.md  # SBOM, dependency provenance, typosquatting
│           ├── container-security.md     # Dockerfile, Kubernetes RBAC, pod security
│           ├── cicd-security.md          # GitHub Actions, GitLab CI, Vercel builds
│           ├── secret-scanning.md        # Git history, build artifacts, rotation
│           ├── llm-security.md           # OWASP Top 10 for LLM, MCP, RAG security
│           └── best-practices-analysis.md # Cross-cutting best-practice review
├── SKILL.md -> plugins/security-audit/skills/security-audit/SKILL.md      # symlink, keeps plain-clone installs working
├── references -> plugins/security-audit/skills/security-audit/references  # symlink, same
├── scripts -> plugins/security-audit/skills/security-audit/scripts        # symlink, same
├── tests/test_audit_workflow.py           # Disposable-project CLI regression tests
└── README.md                             # This file
```

### Design Principles

- **Progressive Disclosure** — SKILL.md stays concise. Detailed grep patterns, SQL queries, and CLI commands live in `references/`, loaded only when needed. ([Anthropic best practice](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices))
- **Evidence-First** — Every finding includes file path, line number, and a concrete remediation. Inspired by [Trail of Bits skills](https://github.com/trailofbits/skills).
- **CLI + Chrome MCP** — Automate what CLI/API can reach; use Chrome DevTools MCP for dashboard-only settings.
- **Standards-Based** — All checks map to established standards (OWASP, CIS, PCI-DSS, GDPR, etc.).

## Audit Phases

| Phase | Target | Method |
|-------|--------|--------|
| 1. Reconnaissance | Project structure | Glob, Read |
| 2. Web Application | Next.js, general web | Grep, Bash |
| 3. Infrastructure | Vercel, Supabase, Terraform, AWS, GCP, Azure | CLI, Chrome MCP, Grep |
| 4. Backend | Python, Go, Rails, Rust | Grep, Bash |
| 5. Mobile | iOS, Android, Flutter, React Native | Grep, Bash |
| 6. Compliance | PCI-DSS, HIPAA, GDPR, SOC2, ISO27001 | Grep, Analysis |
| 7. Advanced | Supply chain, containers, CI/CD, secrets, LLM | Grep, Bash |
| 8. Cross-Layer | Auth flow, token lifecycle, data protection | Analysis |

## Roadmap

### v1.0
- [x] Next.js (App Router, Server Actions, Middleware, CSP)
- [x] Vercel (env vars, WAF, deployment protection, security headers)
- [x] Supabase (RLS, Auth, Storage, Edge Functions, Splinter lint)
- [x] iOS (MASVS v2 / MASTG all 8 categories)
- [x] General Web (OWASP WSTG + Top 10:2025)
- [x] Chrome MCP dashboard inspection

### v1.1 — Mobile Expansion
- [x] Android (MASVS v2 / MASTG — Kotlin/Java)
- [x] Flutter (Dart security patterns, platform channel security)
- [x] React Native security patterns

### v1.2 — Backend Expansion
- [x] Python (Django, FastAPI, Flask — OWASP + Bandit patterns)
- [x] Go (common vulnerability patterns, goroutine safety)
- [x] Ruby on Rails (Brakeman patterns)
- [x] Rust (unsafe blocks, memory safety audit)

### v1.3 — Infrastructure as Code
- [x] Terraform (AWS/GCP/Azure misconfigurations)
- [x] AWS Well-Architected Framework (Security Pillar)
- [x] GCP Security Best Practices
- [x] Azure Security Benchmark

### v1.4 — Compliance & Regulatory
- [x] Financial-grade security (PCI-DSS v4.0, SOX compliance)
- [x] HIPAA (healthcare data protection)
- [x] GDPR / CCPA (privacy compliance)
- [x] SOC 2 Type II controls mapping
- [x] ISO 27001 controls verification

### v1.5 — Advanced Detection
- [x] Supply chain security (SBOM, dependency provenance)
- [x] Container security (Dockerfile, Kubernetes RBAC)
- [x] CI/CD pipeline security (GitHub Actions, Vercel builds)
- [x] Secret scanning (git history, build artifacts)
- [x] LLM/AI security (OWASP Top 10 for LLM)

### v2.0 — Next Generation (In Progress)
- [ ] Auto-fix mode (generate PRs with remediation)
- [x] Severity scoring with CVSS v4.0 (available in this revision)
- [x] Custom rule engine (trusted user-defined JSON regex patterns, with execution deadlines)
- [x] Integration with external scanners (POSIX runners for installed Semgrep and existing CodeQL databases, plus SARIF import)
- [x] Continuous monitoring mode (local custom-rule polling with a fixed baseline)

CVSS support is an instruction-based assessment and reporting workflow, not a bundled scoring engine. It requires the FIRST CVSS v4.0 calculator or a verified v4.0 implementation, records metric evidence and calculation sources, and explicitly reports Unscored and N/A findings. See [the scoring guide](plugins/security-audit/skills/security-audit/references/cvss-scoring.md).

### v2.0 workflow support (v1.9.0)

Custom rules, local continuous monitoring, and external scanner runners are available. Auto-fix PR generation remains in progress:

| Item | Available now | Remaining scope |
|------|---------------|-----------------|
| Auto-fix PRs | Evidence-based remediation workflow and read-only patch validation | End-to-end automated remediation and PR generation |
| Custom rule engine | Trusted local JSON regex rules with bounded UTF-8 file scanning and process execution deadlines | Optional language-aware rules; no sandbox or memory quota for untrusted patterns |
| External scanners | POSIX execution of installed Semgrep / existing CodeQL databases with SARIF 2.1.0 normalization | Optional installation/database lifecycle management, Windows runners, and broader SARIF coverage |
| Continuous monitoring | Compatible snapshot comparison and local polling watch, with optional failure on new findings | Optional scanner-backed monitoring, advisory feeds, and external scheduling |

Use `/security-audit custom`, `scanner`, `monitor`, `watch`, or `fix` to request these agent workflows. The bundled Python 3.10+ helper prints JSON (NDJSON for `watch`) to stdout and does not install scanners, apply patches, create PRs, register schedules, or update baselines. See [workflow commands, limitations, and authorization](plugins/security-audit/skills/security-audit/references/advanced-workflows.md).

Semgrep execution is verified against an actual scanner. CodeQL runner arguments, result normalization, failure handling, and process cleanup are tested with a stand-in executable; running the native CodeQL engine requires a separately prepared local installation, database, and query suite.

From a repository checkout, run the helper tests with:

```bash
python3 -m unittest discover -s tests -v
```

## References

- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)
- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP MASVS v2](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [OWASP Top 10 for LLM](https://genai.owasp.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/)
- [Trail of Bits Security Skills](https://github.com/trailofbits/skills)
- [Anthropic Skill Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)

## Contributing

PRs welcome! When adding a new reference:

1. Create `plugins/security-audit/skills/security-audit/references/<technology>-security.md`
2. Follow the existing format: detection patterns (grep/bash), Chrome MCP steps, common misconfigs table, checklist
3. Add the technology to the relevant phase in `plugins/security-audit/skills/security-audit/SKILL.md`
4. Update this README's roadmap
5. Bump `version` in `plugins/security-audit/.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`
6. Run `claude plugin validate .` and `claude plugin validate plugins/security-audit`

## License

MIT
