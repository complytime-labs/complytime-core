# SPDX-License-Identifier: Apache-2.0

INGEST_IMAGE ?= complytime-ingest
INGEST_TAG ?= local
CONTAINER_RUNTIME ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: test test-integration lint lint-openapi clean \
	ingest-build ingest-build-fips ingest-image \
	monitor-build monitor-build-fips monitor-image

test:
	go test -tags dev -v -race -cover ./...

test-integration:
	go test -v -race -cover -tags integration ./internal/e2e/...

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
	docker build --no-cache -f Dockerfile.monitor -t complytime-monitor:local .
