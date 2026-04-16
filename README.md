🔗 Disponível em [Português](./README.pt-BR.md).

---

# Pipeline AppSec — Centralized Security Orchestration

This repository centralizes the Application Security (AppSec) pipeline, providing automated, policy-driven scans for the organization's projects. Built with GitHub Actions and a Python orchestration layer, it ensures compliance, simplifies false-positive management, and offers flexible policy enforcement without slowing down development.

## Architecture Strategy

The pipeline is designed to act as a hub where individual repositories call a reusable centralized workflow. This allows keeping policies and security tooling in a single place while execution runs natively in contributors' PR flows.

- **Caller Workflow (`security-pipeline.yml`):**
	This workflow lives in each integrated repository and acts as the entry point to the centralized pipeline. It calls the shared `appsec-pipeline.yml`, inheriting secrets and passing repository-specific parameters. It is triggered on pull requests (opened, synchronized, or reopened), manual dispatch, and on a daily schedule at **5:00 AM (UTC-3)**, ensuring continuous security coverage even without PR activity.

- **Orchestration via GitHub Actions (`appsec-pipeline.yml`):**
	The orchestrator runs security tools in parallel jobs to optimize response time. Each tool exports results in the standardized SARIF format and stores them as artifacts.

- **Security GATE (`gate.py`):**
	To avoid relying solely on individual tools' exit codes, the `security-gate` job consolidates all SARIF artifacts. A Python script parses the data and validates it against a centralized severity policy (`severity-policy.yml`).

- **Findings & False-Positive Management (`exception_manager.py` & `security-exceptions.yml`):**
	False-positive handling is isolated from application source code to avoid inline suppression comments. Through a dedicated workflow, AppSec teams manage exceptions via the GitHub Actions interface. Authorized vulnerabilities are stored in `exception.yml`, and the pipeline core filters them out before the final GATE validation.

- **Automated Onboarding (`setup_repo.py`):**
	New repositories integrate via a script that automatically configures branch protection rules (making the GATE mandatory and protecting the main branch) and propagates the workflow call files.

---

## Tools and Rationale

We prioritize high-performance open-source tools to avoid vendor lock-in and ensure transparency in detection rules.

|**Domain**|**Tool**|**Rationale**|
|---|---|---|
|**SAST**|**Semgrep**|Lightweight and fast. Rule syntax mirrors source code, easing custom policy creation.|
|**SCA**|**Trivy**|A reference for mapping vulnerabilities (CVEs) in dependencies and open-source packages with a low false-positive rate.|
|**IaC**|**Trivy**|Consolidates scanning for infrastructure (Terraform, K8s, Docker) using the same engine as SCA.|
|**Secrets**|**Gitleaks**|Specialized in detecting API keys and tokens exposed in Git history with high performance.|
|**Mobile SAST**|**MobSFscan**|Focused on iOS and Android vulnerabilities that generic scanners often miss.|

---

## Governance and Execution

The pipeline separates visibility from enforceability: it gives continuous feedback without unnecessarily blocking development.

### Blocking vs Alerts

Behavior is defined by `severity-policy.yml`, which sets a blocking threshold (`block_on`) per category.

- **Non-blocking:** Findings below the threshold (e.g., `LOW`) appear in the GitHub Step Summary for hygiene purposes but do not fail the pipeline.

- **Blocking:** Vulnerabilities meeting or exceeding the threshold (e.g., `HIGH`) cause the `security-gate` job to fail, blocking merges into protected branches.

### Exceptions (Suppression)

If a blocking finding is a false positive or an accepted risk, AppSec can suppress it via the exception management workflow. Once recorded in `exception.yml`, the GATE ignores the item and the pipeline proceeds successfully.

### Emergency Bypass

In critical situations (e.g., a hotfix with no time to go through exception flow), AppSec may bypass the gate by commenting `/sec-bypass <justification>` on the PR. The `check-bypass` job validates the command and the GATE allows the deployment while logging the responsible user and justification for auditing.

## Integrated Vulnerable Repositories

Below are the 4 vulnerable repositories used for pipeline integration and testing:

- **OWASP Juice Shop (Node.js/TypeScript - Web)** — https://github.com/jvrajunior/juice-shop
- **VAmPI (Python/Flask - API)** — https://github.com/jvrajunior/VAmPI
- **Terragoat (Terraform - AWS)** — https://github.com/jvrajunior/terragoat
- **diva-android (Java - Android)** — https://github.com/jvrajunior/diva-android