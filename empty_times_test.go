package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"testing"
)

func TestEntryWithEmptyTimeElementParses(t *testing.T) {
	// Empty times must not cause an entry (and its protected values) to be skipped.
	var g Group
	data := `<Group><Entry><Times><ExpiryTime/></Times>` +
		`<String><Key>Password</Key><Value Protected="True">YWJj</Value></String>` +
		`</Entry></Group>`
	if err := xml.Unmarshal([]byte(data), &g); err != nil {
		t.Fatalf("Group with an empty timestamp failed to parse: %s", err)
	}
	if len(g.Entries) != 1 {
		t.Fatalf("Expected 1 entry, received %d", len(g.Entries))
	}
	if got := g.Entries[0].GetPassword(); got != "YWJj" {
		t.Errorf("Expected preserved protected value YWJj, received %q", got)
	}
}

func assertEmptyTimesContent(t *testing.T, db *Database) {
	t.Helper()

	expected := map[string]string{
		"t1":       "PASS-1",
		"t2":       "PASS-2",
		"t3":       "PASS-3",
		"t4":       "PASS-4",
		"t5":       "PASS-5",
		"t6-in-g1": "PASS-6",
	}
	for title, want := range expected {
		entry := findEntryByTitle(db.Content.Root.Groups, title)
		if entry == nil {
			t.Fatalf("Entry %q not found", title)
		}
		if got := entry.GetPassword(); got != want {
			t.Errorf("Entry %q: expected password %q, received %q", title, want, got)
		}
	}

	e3 := findEntryByTitle(db.Content.Root.Groups, "t3")
	if len(e3.Histories) != 1 || len(e3.Histories[0].Entries) != 1 {
		t.Fatal("Entry t3: expected one history entry")
	}
	if got := e3.Histories[0].Entries[0].GetPassword(); got != "PASS-3-old" {
		t.Errorf("Entry t3 history: expected password PASS-3-old, received %q", got)
	}
	if e3.Times.ExpiryTime == nil || !e3.Times.ExpiryTime.Time.IsZero() {
		t.Errorf("Entry t3: expected zero expiry time, received %+v", e3.Times.ExpiryTime)
	}
	if db.Content.Meta.MasterKeyChanged == nil || !db.Content.Meta.MasterKeyChanged.Time.IsZero() {
		t.Errorf("Expected zero MasterKeyChanged, received %+v", db.Content.Meta.MasterKeyChanged)
	}
}

func TestDecodeFileEmptyTimes31(t *testing.T) {
	// Generated with kdbxweb 1.14.4, password "123". Contains empty times in
	// Meta, entries and history. All entries after them must decrypt correctly.
	db := decodeDatabase(t, "tests/kdbx3/kdbxweb-empty-times.kdbx", interopPassword)
	assertEmptyTimesContent(t, db)

	for range 2 {
		if err := db.LockProtectedEntries(); err != nil {
			t.Fatalf("Failed to lock entries: %s", err)
		}
		var buf bytes.Buffer
		if err := NewEncoder(&buf).Encode(db); err != nil {
			t.Fatalf("Failed to encode file: %s", err)
		}
		db = NewDatabase()
		db.Credentials = NewPasswordCredentials(interopPassword)
		if err := NewDecoder(&buf).Decode(db); err != nil {
			t.Fatalf("Failed to decode saved file: %s", err)
		}
		if err := db.UnlockProtectedEntries(); err != nil {
			t.Fatalf("Failed to unlock saved entries: %s", err)
		}
		assertEmptyTimesContent(t, db)
	}
}
