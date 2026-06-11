// SPDX-License-Identifier: Apache-2.0

//go:build integration

package blob

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Integration tests against a real S3-compatible endpoint. Example:
//
//	docker run -p 9000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
//	  quay.io/minio/minio server /data
//
//	BLOB_INTEGRATION=1 BLOB_ENDPOINT=127.0.0.1:9000 BLOB_BUCKET=test-evidence \
//	  BLOB_ACCESS_KEY=minioadmin BLOB_SECRET_KEY=minioadmin BLOB_USE_SSL=false \
//	  go test ./internal/blob/ -run Integration -count=1

func TestMinioBlobStore_IntegrationHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if os.Getenv("BLOB_INTEGRATION") == "" {
		t.Skip("set BLOB_INTEGRATION=1 and BLOB_* env vars to run against MinIO")
	}
	cfg, ok := ConfigFromEnv()
	if !ok {
		t.Fatal("BLOB_INTEGRATION set but BLOB_ENDPOINT missing")
	}
	ctx := context.Background()
	store, err := NewMinioBlobStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Upload(ctx, EvidenceObjectKey("report.pdf"), strings.NewReader("hello-evidence"), 14)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBlobRef(ref); err != nil {
		t.Fatal(err)
	}
}

func TestMinioBlobStore_IntegrationPutCanceled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if os.Getenv("BLOB_INTEGRATION") == "" {
		t.Skip("set BLOB_INTEGRATION=1 and BLOB_* env vars")
	}
	cfg, ok := ConfigFromEnv()
	if !ok {
		t.Fatal("BLOB_ENDPOINT required")
	}
	ctx := context.Background()
	store, err := NewMinioBlobStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.Upload(ctx2, EvidenceObjectKey("gone.txt"), strings.NewReader("x"), 1)
	if err == nil {
		t.Fatal("expected canceled context to fail PutObject")
	}
}
