# SPDX-License-Identifier: Apache-2.0

NAMESPACE ?= kagent
INGEST_IMAGE ?= complytime-ingest
INGEST_TAG ?= local
CONTAINER_RUNTIME ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
KIND_CLUSTER ?= complytime-studio

.PHONY: test lint clean \
	ingest-build ingest-build-fips ingest-image \
	monitor-build monitor-build-fips monitor-image \

	compose-up seed \
	cluster-up cluster-down \
	oidc-secret \
	demo demo-change demo-all

test:
	go test -v -race -cover ./...

test-integration:
	@test -n "$(POSTGRES_TEST_URL)" || (echo "POSTGRES_TEST_URL required — e.g. postgres://user:pass@localhost:5432/test?sslmode=disable" && exit 1)
	POSTGRES_TEST_URL=$(POSTGRES_TEST_URL) go test -v -race -cover -tags integration ./...

lint:
	golangci-lint run ./...

lint-openapi:
	go test ./internal/api/... -run TestSpecDrift -v -count=1

clean:
	rm -rf bin/

ingest-build:
	go build -o bin/complytime-ingest ./cmd/ingest/

ingest-build-fips:
	GOFIPS140=latest go build -o bin/complytime-ingest ./cmd/ingest/

ingest-image:
	docker build --no-cache -f Dockerfile.ingest -t $(INGEST_IMAGE):$(INGEST_TAG) .

monitor-build:
	go build -o bin/monitor ./cmd/monitor/

monitor-build-fips:
	GOFIPS140=latest go build -o bin/monitor ./cmd/monitor/

monitor-image:
	docker build --no-cache -f Dockerfile.monitor -t studio-monitor:local .

compose-up:
	@echo "Docker Compose moved to studio-deploy. Run: cd ../studio-deploy && make up"
	@exit 1

cluster-up:
	@./deploy/kind/setup.sh

cluster-down:
	kind delete cluster --name complytime-studio

# Helm targets moved to studio-deploy repo.
# See: ../studio-deploy/Makefile (helm-template, helm-install, helm-upgrade)

# Create the Kubernetes secret for OIDC credentials.
# Usage: OIDC_CLIENT_SECRET=<secret> make oidc-secret
oidc-secret:
	@if [ -z "$$OIDC_CLIENT_SECRET" ]; then \
		echo "error: OIDC_CLIENT_SECRET is required"; exit 1; \
	fi
	kubectl create secret generic studio-oauth-credentials \
		--namespace $(NAMESPACE) \
		--from-literal=client-secret="$$OIDC_CLIENT_SECRET" \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "Secret studio-oauth-credentials written to namespace $(NAMESPACE)"

# Full deploy cycle moved to studio-deploy repo.
# Use: cd ../studio-deploy && make helm-install

# Seed demo data into a running Studio instance.
# Port-forwards to the gateway container (bypassing OAuth2 Proxy).
# Identity is injected via X-Forwarded-Email header.
SEED_PORT ?= 9090
seed:
	@echo "Port-forwarding to gateway pod (bypassing OAuth2 Proxy)..."
	@kubectl port-forward -n $(NAMESPACE) deployment/studio-gateway $(SEED_PORT):8080 &
	@sleep 2
	@GATEWAY_URL=http://localhost:$(SEED_PORT) ./demo/seed.sh; \
		EXIT_CODE=$$?; \
		kill %1 2>/dev/null; \
		exit $$EXIT_CODE

# Record the baseline SOC 2 gap analysis demo video.
# Output: demo/cypress/videos/soc2-gap-analysis.cy.js.mp4
demo:
	cd demo && npx cypress run --no-runner-ui --spec 'cypress/e2e/soc2-gap-analysis.cy.js'

# Record demo video for a specific change.
# Usage: CHANGE=generic-oidc-auth make demo-change
demo-change:
	@if [ -z "$$CHANGE" ]; then echo "error: CHANGE is required (e.g. CHANGE=generic-oidc-auth make demo-change)"; exit 1; fi
	cd demo && npx cypress run --no-runner-ui --spec "cypress/e2e/$$CHANGE-demo.cy.js"

# Record all demo videos (baseline + all change demos).
# Output: demo/cypress/videos/*.mp4
demo-all:
	cd demo && npx cypress run --no-runner-ui --spec 'cypress/e2e/*.cy.js'
