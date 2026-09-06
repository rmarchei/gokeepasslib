package gokeepasslib

import (
	"bytes"
	"testing"
)

func TestEncodeRemovesUnusedProtectedBinary(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx3/protected-binary.kdbx", interopPassword)
	entry := findEntryByTitle(db.Content.Root.Groups, "e2-in-g1")
	if entry == nil {
		t.Fatal("Expected attachment entry")
	}
	entry.Binaries = nil

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Failed to lock entries: %s", err)
	}
	var buf bytes.Buffer
	if err := NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Failed to encode file: %s", err)
	}
	if len(db.Content.Meta.Binaries) != 0 {
		t.Fatal("Expected unused binary to be removed")
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock live database: %s", err)
	}
	assertInteropContent(t, db)

	reopened := NewDatabase()
	reopened.Credentials = NewPasswordCredentials(interopPassword)
	if err := NewDecoder(&buf).Decode(reopened); err != nil {
		t.Fatalf("Failed to decode saved database: %s", err)
	}
	if err := reopened.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock saved database: %s", err)
	}
	assertInteropContent(t, reopened)
}
