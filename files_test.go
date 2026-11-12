package shuffle

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStorageKeyStripsBasepath(t *testing.T) {
	cases := []struct {
		base, path, expected string
	}{
		{"/shuffle-files", "/shuffle-files/large_executions/org1/exec_1_action_1", "large_executions/org1/exec_1_action_1"},
		{"/shuffle-files", "large_executions/org1/exec_1_action_1", "large_executions/org1/exec_1_action_1"},
		{"", "large_executions/org1/x", "large_executions/org1/x"},
		{"/shuffle-files", "/other/place/file", "other/place/file"},
	}

	for _, c := range cases {
		basepath = c.base
		got := storageKey(c.path)
		if got != c.expected {
			t.Errorf("storageKey(%q) with base %q = %q, expected %q", c.path, c.base, got, c.expected)
		}
	}
	basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
}

func TestWriteReadStorageDataLocal(t *testing.T) {
	tmp := t.TempDir()
	basepath = tmp
	defer func() { basepath = os.Getenv("SHUFFLE_FILE_LOCATION") }()

	rel := "large_executions/org1/exec_1_action_1"
	data := []byte(`{"success": false, "size": 999999}`)

	if err := WriteStorageData(rel, data); err != nil {
		t.Fatalf("WriteStorageData failed: %s", err)
	}

	// Must land in the expected location on disk
	full := filepath.Join(tmp, rel)
	onDisk, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("expected local file at %s: %s", full, err)
	}
	if string(onDisk) != string(data) {
		t.Fatalf("content mismatch on disk")
	}

	// Read back via relative path
	got, err := ReadStorageData(rel)
	if err != nil {
		t.Fatalf("ReadStorageData (relative) failed: %s", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch (relative read)")
	}

	// Read back via absolute path (how legacy call sites pass it)
	got, err = ReadStorageData(full)
	if err != nil {
		t.Fatalf("ReadStorageData (absolute) failed: %s", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch (absolute read)")
	}

	if err := DeleteStorageData(full); err != nil {
		t.Fatalf("DeleteStorageData failed: %s", err)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete")
	}
}

func TestWriteStorageDataLocalCreatesDirectories(t *testing.T) {
	tmp := t.TempDir()
	basepath = tmp
	defer func() { basepath = os.Getenv("SHUFFLE_FILE_LOCATION") }()

	rel := filepath.Join("large_workflows", "nested", "deep", "file")
	if err := WriteStorageData(rel, []byte("x")); err != nil {
		t.Fatalf("WriteStorageData with missing directories failed: %s", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, rel)); err != nil {
		t.Fatalf("expected nested file: %s", err)
	}
}

func TestReadStorageDataLocalMissing(t *testing.T) {
	basepath = t.TempDir()
	defer func() { basepath = os.Getenv("SHUFFLE_FILE_LOCATION") }()

	_, err := ReadStorageData("large_executions/org_missing/does_not_exist")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist-compatible error, got: %s", err)
	}
}

func TestLocalStorageAppend(t *testing.T) {
	tmp := t.TempDir()
	basepath = tmp
	defer func() { basepath = os.Getenv("SHUFFLE_FILE_LOCATION") }()

	key := "org1/global/file_1"

	// Appending to a missing file creates it
	if err := AppendStorageData(nil, key, []byte("chunk1")); err != nil {
		t.Fatalf("first AppendStorageData failed: %s", err)
	}
	if err := AppendStorageData(nil, key, []byte("chunk2")); err != nil {
		t.Fatalf("second AppendStorageData failed: %s", err)
	}

	got, err := ReadStorageData(key)
	if err != nil {
		t.Fatalf("ReadStorageData failed: %s", err)
	}
	if string(got) != "chunk1chunk2" {
		t.Fatalf("append result mismatch: %q", string(got))
	}
}

func TestLocalStorageRejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	basepath = tmp
	defer func() { basepath = os.Getenv("SHUFFLE_FILE_LOCATION") }()

	if err := os.WriteFile(filepath.Join(filepath.Dir(tmp), "outside.txt"), []byte("secret"), 0644); err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(filepath.Dir(tmp), "outside.txt")) })

	if err := WriteStorageData("../outside.txt", []byte("evil")); err == nil {
		t.Fatal("expected path traversal via WriteStorageData to be rejected")
	}
	if _, err := os.ReadFile(filepath.Join(filepath.Dir(tmp), "outside.txt")); err != nil {
		t.Fatalf("file outside storage root unexpectedly modified or missing: %s", err)
	}
}

func TestStorageBackendDefaultsToLocal(t *testing.T) {
	if os.Getenv("SHUFFLE_STORAGE_BACKEND") != "" {
		t.Skip("test expects default SHUFFLE_STORAGE_BACKEND")
	}

	if StorageS3Enabled() {
		t.Fatal("expected local backend by default")
	}
	if StorageAreaName() != "local" {
		t.Fatalf("expected StorageAreaName 'local', got %q", StorageAreaName())
	}
}

func TestS3StorageIntegration(t *testing.T) {
	endpoint := os.Getenv("SHUFFLE_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SHUFFLE_TEST_S3_ENDPOINT not set; skipping S3 integration test")
	}

	bucket := os.Getenv("SHUFFLE_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "shuffle-test"
	}

	accessKey := os.Getenv("SHUFFLE_TEST_S3_ACCESS_KEY")
	secretKey := os.Getenv("SHUFFLE_TEST_S3_SECRET_KEY")

	t.Setenv("SHUFFLE_S3_ENDPOINT", endpoint)
	t.Setenv("SHUFFLE_S3_BUCKET", bucket)
	t.Setenv("SHUFFLE_S3_ACCESS_KEY", accessKey)
	t.Setenv("SHUFFLE_S3_SECRET_KEY", secretKey)

	// Reset the per-process backend so the env configuration applies
	storageBackendOnce = *new(sync.Once)
	storageBackendErr = nil
	if !StorageS3Enabled() {
		t.Fatalf("expected s3 backend, backendErr: %v", storageBackendErr)
	}
	t.Cleanup(func() {
		storageBackendOnce = *new(sync.Once)
		storageBackendErr = nil
	})

	key := "large_executions/testorg/testexec_testaction"

	if err := WriteStorageData(key, []byte("hello")); err != nil {
		t.Fatalf("WriteStorageData failed: %s", err)
	}

	got, err := ReadStorageData(key)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadStorageData failed: %v (%q)", err, string(got))
	}

	// Append twice: creates then extends
	if err := AppendStorageData(nil, key+"_append", []byte("a")); err != nil {
		t.Fatalf("first AppendStorageData failed: %s", err)
	}
	if err := AppendStorageData(nil, key+"_append", []byte("b")); err != nil {
		t.Fatalf("second AppendStorageData failed: %s", err)
	}
	got, err = ReadStorageData(key + "_append")
	if err != nil || string(got) != "ab" {
		t.Fatalf("append result mismatch: %v (%q)", err, string(got))
	}

	if err := DeleteStorageData(key); err != nil {
		t.Fatalf("DeleteStorageData failed: %s", err)
	}

	// Missing keys must produce os.IsNotExist-compatible errors
	_, err = ReadStorageData(key)
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist error after delete, got: %s", err)
	}
}
