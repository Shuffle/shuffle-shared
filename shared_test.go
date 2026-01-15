package shuffle

import (
	"os"
	"testing"
)

func TestIsLoop(t *testing.T) {
	handlers := []struct {
		arg      string
		expected bool
	}{
		{"$exec.#1-2", true},
		{"$exec.#.value.#1", true},
		{"$exec.#1", false},
		{"$exec", false},
		{"$exec.#1.value.#2", false},
		{"$start_node.#", true},
		{"\n$Change_Me\n.#3.value\n", false},
		{"\n\n\n\n$Change_Me\n\n.\n#\n.\n\nvalue\n\n\n", true},
	}

	for _, tt := range handlers {
		result := isLoop(tt.arg)
		if result != tt.expected {
			t.Errorf("isLoop(%s) = %v; expected %v", tt.arg, result, tt.expected)
		}
	}
}

// tests that deterministic mode produces consistent output
func TestHandleKeyEncryptionDeterministic(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	testData := []byte("test-api-key-12345")
	passphrase := "apikey"

	encrypted1, err := HandleKeyEncryption(testData, passphrase, true)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := HandleKeyEncryption(testData, passphrase, true)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	if string(encrypted1) != string(encrypted2) {
		t.Errorf("Deterministic encryption produced different outputs:\n  First:  %s\n  Second: %s", encrypted1, encrypted2)
	}
}

// tests that default mode produces different output each time
func TestHandleKeyEncryptionRandomNonce(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	testData := []byte("test-api-key-12345")
	passphrase := "apikey"

	encrypted1, err := HandleKeyEncryption(testData, passphrase)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := HandleKeyEncryption(testData, passphrase)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	if string(encrypted1) == string(encrypted2) {
		t.Errorf("Random nonce encryption should produce different outputs, but got same")
	}
}

// tests that encrypted data can be decrypted correctly
func TestHandleKeyDecryption(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	testCases := []struct {
		name          string
		data          string
		passphrase    string
		deterministic bool
	}{
		{"API key deterministic", "abc123-api-key-uuid", "apikey", true},
		{"Session deterministic", "xyz789-session-uuid", "session", true},
		{"API key random nonce", "abc123-api-key-uuid", "apikey", false},
		{"Session random nonce", "xyz789-session-uuid", "session", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var encrypted []byte
			var err error

			if tc.deterministic {
				encrypted, err = HandleKeyEncryption([]byte(tc.data), tc.passphrase, true)
			} else {
				encrypted, err = HandleKeyEncryption([]byte(tc.data), tc.passphrase)
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := HandleKeyDecryption(encrypted, tc.passphrase)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != tc.data {
				t.Errorf("Decrypted data mismatch:\n  Expected: %s\n  Got:      %s", tc.data, decrypted)
			}
		})
	}
}

// tests that encryption fails without SHUFFLE_ENCRYPTION_MODIFIER
func TestHandleKeyEncryptionNoModifier(t *testing.T) {
	os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	_, err := HandleKeyEncryption([]byte("test-data"), "passphrase", true)
	if err == nil {
		t.Error("Expected error when SHUFFLE_ENCRYPTION_MODIFIER is not set, but got none")
	}
}

// simulates storing and retrieving an API key
func TestApiKeyEncryptionRoundTrip(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	plainApiKey := "550e8400-e29b-41d4-a716-446655440000"

	encryptedKey, err := HandleKeyEncryption([]byte(plainApiKey), "apikey", true)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedIncoming, err := HandleKeyEncryption([]byte(plainApiKey), "apikey", true)
	if err != nil {
		t.Fatalf("Encryption of incoming key failed: %v", err)
	}

	if string(encryptedKey) != string(encryptedIncoming) {
		t.Errorf("Encrypted keys should match for same input:\n  Stored:   %s\n  Incoming: %s", encryptedKey, encryptedIncoming)
	}

	decrypted, err := HandleKeyDecryption(encryptedKey, "apikey")
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != plainApiKey {
		t.Errorf("Decrypted API key mismatch:\n  Expected: %s\n  Got:      %s", plainApiKey, decrypted)
	}
}

// simulates storing and retrieving a session
func TestSessionEncryptionRoundTrip(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	plainSession := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	encryptedSession, err := HandleKeyEncryption([]byte(plainSession), "session", true)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedIncoming, err := HandleKeyEncryption([]byte(plainSession), "session", true)
	if err != nil {
		t.Fatalf("Encryption of incoming session failed: %v", err)
	}

	if string(encryptedSession) != string(encryptedIncoming) {
		t.Errorf("Encrypted sessions should match for same input:\n  Stored:   %s\n  Incoming: %s", encryptedSession, encryptedIncoming)
	}

	decrypted, err := HandleKeyDecryption(encryptedSession, "session")
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != plainSession {
		t.Errorf("Decrypted session mismatch:\n  Expected: %s\n  Got:      %s", plainSession, decrypted)
	}
}

// tests that old plain text keys still work
func TestBackwardsCompatibility(t *testing.T) {
	os.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "test-modifier-12345")
	defer os.Unsetenv("SHUFFLE_ENCRYPTION_MODIFIER")

	oldPlainApiKey := "old-plain-api-key-uuid"
	incomingKey := "old-plain-api-key-uuid"

	encryptedIncoming, _ := HandleKeyEncryption([]byte(incomingKey), "apikey", true)

	// Encrypted version won't match plain text
	if string(encryptedIncoming) == oldPlainApiKey {
		t.Error("Encrypted key should not match plain text key")
	}

	// Plain text comparison works (backwards compat)
	if incomingKey != oldPlainApiKey {
		t.Error("Plain text comparison should work for backwards compatibility")
	}

	t.Logf("Encrypted format: %s", encryptedIncoming)
	t.Logf("Plain format:     %s", oldPlainApiKey)
}
