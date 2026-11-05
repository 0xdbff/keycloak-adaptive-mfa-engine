SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help security-scan scan-secrets scan-sast scan-deps scan-dockerfile \
        scan-container check-hadolint check-trivy check-gitleaks \
        check-semgrep check-docker

IMAGE_TAG ?= keycloak-amfa:scan
TRIVY_SEVERITY ?= CRITICAL,HIGH,MEDIUM
SEMGREP_CONFIG ?= auto
DOCKERFILES := Dockerfile config/keycloak/Dockerfile.keycloak

help:
	@echo "keycloak-amfa targets:"
	@echo "  security-scan     Run the full security battery (mirrors CI)."
	@echo "  scan-secrets      Gitleaks: full-history secret scan."
	@echo "  scan-sast         Semgrep: static analysis with the auto ruleset."
	@echo "  scan-deps         Trivy fs: dependency CVE scan against the repo."
	@echo "  scan-dockerfile   Hadolint: lint both Dockerfiles."
	@echo "  scan-container    Docker build + Trivy image scan of the engine image."

security-scan: scan-secrets scan-sast scan-deps scan-dockerfile scan-container
	@echo ""
	@echo "All scans finished. See individual tool output above for findings."

scan-secrets: check-gitleaks
	@echo "→ gitleaks (full history)"
	gitleaks detect --source . --redact --no-banner --report-format json --report-path gitleaks-report.json || true

scan-sast: check-semgrep
	@echo "→ semgrep ($(SEMGREP_CONFIG))"
	semgrep scan --config $(SEMGREP_CONFIG) --json --output semgrep-report.json --quiet || true
	@if command -v jq >/dev/null 2>&1; then \
	  echo "$$(jq '.results | length' semgrep-report.json) finding(s):"; \
	  jq -r '.results[] | "  [\(.check_id)] \(.path):\(.start.line)"' semgrep-report.json; \
	else \
	  echo "  (install jq for a formatted summary; raw report at semgrep-report.json)"; \
	fi

scan-deps: check-trivy
	@echo "→ trivy fs (dependencies)"
	trivy fs --scanners vuln --severity $(TRIVY_SEVERITY) --ignore-unfixed --exit-code 0 .
	trivy fs --scanners vuln --format json --output trivy-fs-report.json .

scan-dockerfile: check-hadolint
	@echo "→ hadolint"
	hadolint $(DOCKERFILES) || true
	hadolint --format json $(DOCKERFILES) > hadolint-report.json || true

scan-container: check-docker check-trivy
	@echo "→ docker build $(IMAGE_TAG)"
	docker build -t $(IMAGE_TAG) .
	@echo "→ trivy image $(IMAGE_TAG)"
	trivy image --timeout 20m --scanners vuln --severity $(TRIVY_SEVERITY) --ignore-unfixed --exit-code 0 $(IMAGE_TAG)
	trivy image --timeout 20m --scanners vuln --severity $(TRIVY_SEVERITY) --ignore-unfixed --format json --output trivy-image-report.json $(IMAGE_TAG)

check-hadolint:
	@command -v hadolint >/dev/null 2>&1 || { \
	  echo "hadolint not found. Install: brew install hadolint"; exit 1; }

check-trivy:
	@command -v trivy >/dev/null 2>&1 || { \
	  echo "trivy not found. Install: brew install trivy"; exit 1; }

check-gitleaks:
	@command -v gitleaks >/dev/null 2>&1 || { \
	  echo "gitleaks not found. Install: brew install gitleaks"; exit 1; }

check-semgrep:
	@command -v semgrep >/dev/null 2>&1 || { \
	  echo "semgrep not found. Install: brew install semgrep  # or: pipx install semgrep"; exit 1; }

check-docker:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "docker not found. Install Docker Desktop or the Docker Engine."; exit 1; }
