package gokeepasslib

import (
	"bytes"
	"fmt"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// base64LikeContents are attachments which are valid base64 to the decoder,
// which skips line breaks. KDBX 4 stores them as they are in the inner header
var base64LikeContents = [][]byte{
	[]byte("QUJDRA=="),
	[]byte("QUJDRA==\n"),
	[]byte("QUJD\r\nRA=="),
	[]byte("ABCD"),
	[]byte("\n"),
	{},
}

func assertBinaryContent(t *testing.T, binary *Binary, expected []byte) {
	t.Helper()

	data, err := binary.GetContentBytes()
	if err != nil {
		t.Fatalf("Failed to read binary with content %q: %s", expected, err)
	}
	// Callers tell an empty attachment from a missing one by a nil slice
	if data == nil {
		t.Errorf("Expected content %q, received nil", expected)
	}
	if !bytes.Equal(data, expected) {
		t.Errorf("Expected content %q, received %q", expected, data)
	}

	// Changing the returned content must not change the binary
	for i := range data {
		data[i] ^= 0xff
	}
	if data, err := binary.GetContentBytes(); err != nil || !bytes.Equal(data, expected) {
		t.Errorf("Expected content %q after changing the returned one, received %q", expected, data)
	}
}

func TestBinaryKDBXv4ContentLookingLikeBase64(t *testing.T) {
	for _, content := range base64LikeContents {
		t.Run(fmt.Sprintf("%q", content), func(t *testing.T) {
			db := NewDatabase(WithDatabaseKDBXVersion40())
			db.Credentials = NewPasswordCredentials(password)
			binary := db.AddBinary(content)
			if !binary.isKDBX4 {
				t.Fatal("Expected an added binary of the inner header to be a KDBX 4 binary")
			}
			assertBinaryContent(t, binary, content)

			entry := NewEntry()
			entry.Binaries = append(entry.Binaries, binary.CreateReference("a.txt"))
			db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

			read := saveAndReopen(t, db).FindBinary(entry.Binaries[0].Value.ID)
			if read == nil || !read.isKDBX4 {
				t.Fatal("Expected a decoded binary of the inner header to be a KDBX 4 binary")
			}
			assertBinaryContent(t, read, content)
		})
	}
}

func TestBinaryXMLContentLookingLikeBase64(t *testing.T) {
	// Every content as a compressed and an uncompressed binary, and as a
	// protected one with and without the Compressed flag, which it ignores
	protected := w.NewBoolWrapper(true)
	kinds := []Binary{
		{Compressed: w.NewBoolWrapper(true)},
		{Compressed: w.NewBoolWrapper(false)},
		{Protected: &protected},
		{Compressed: w.NewBoolWrapper(true), Protected: &protected},
	}
	versions := []struct {
		title  string
		option DatabaseOption
	}{
		{title: "KDBX 3.1", option: WithDatabaseKDBXVersion3()},
		// The XML document of a KDBX 4 file may contain binaries as well
		{title: "KDBX 4", option: WithDatabaseKDBXVersion40()},
	}

	for _, version := range versions {
		t.Run(version.title, func(t *testing.T) {
			db := NewDatabase(version.option)
			db.Credentials = NewPasswordCredentials(password)

			expected := make([][]byte, 0, len(base64LikeContents)*len(kinds))
			entry := NewEntry()
			for _, content := range base64LikeContents {
				for _, binary := range kinds {
					binary.ID = len(expected)
					if err := binary.SetContent(content); err != nil {
						t.Fatalf("Failed to set content %q: %s", content, err)
					}
					db.Content.Meta.Binaries = append(db.Content.Meta.Binaries, binary)
					entry.Binaries = append(entry.Binaries, binary.CreateReference("a.txt"))
					expected = append(expected, content)
				}
			}
			db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

			reopened := saveAndReopen(t, db)
			for _, current := range []*Database{db, reopened} {
				binaries := current.Content.Meta.Binaries
				if len(binaries) != len(expected) {
					t.Fatalf("Expected %d binaries, received %d", len(expected), len(binaries))
				}
				for i := range binaries {
					if binaries[i].isKDBX4 {
						t.Errorf("Expected binary %d of the XML document to be base64 encoded", i)
					}
					assertBinaryContent(t, &binaries[i], expected[i])
				}
			}
		})
	}
}

// assertAttachments checks that the attachments of the entry with the title
// "attachments" hold the base64LikeContents, stored in the format of db
func assertAttachments(t *testing.T, db *Database) {
	t.Helper()

	entry := findEntryByTitle(db.Content.Root.Groups, "attachments")
	if entry == nil || len(entry.Binaries) != len(base64LikeContents) {
		t.Fatalf("Expected an entry with %d attachments", len(base64LikeContents))
	}
	for i, reference := range entry.Binaries {
		binary := db.FindBinary(reference.Value.ID)
		if binary == nil {
			t.Fatalf("Binary of attachment %q not found", reference.Name)
		}
		if binary.isKDBX4 != db.Header.IsKdbx4() {
			t.Errorf("Attachment %q: expected isKDBX4 to be %t", reference.Name, db.Header.IsKdbx4())
		}
		assertBinaryContent(t, binary, base64LikeContents[i])
	}
}

func newAttachmentsEntry() Entry {
	entry := NewEntry()
	entry.Values = append(entry.Values, ValueData{Key: "Title", Value: V{Content: "attachments"}})
	return entry
}

func TestBinaryContentAfterChangingTheFormat(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion3())
	db.Credentials = NewPasswordCredentials(password)
	entry := newAttachmentsEntry()
	for i, content := range base64LikeContents {
		reference := db.AddBinary(content).CreateReference(fmt.Sprintf("%d.txt", i))
		entry.Binaries = append(entry.Binaries, reference)
	}
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)
	db = saveAndReopen(t, db)
	assertAttachments(t, db)

	// Convert the database to KDBX 4: the content of the binaries of the XML
	// document is added to the new inner header and the references are updated
	contents := make([][]byte, 0, len(db.Content.Meta.Binaries))
	for _, binary := range db.Content.Meta.Binaries {
		content, err := binary.GetContentBytes()
		if err != nil {
			t.Fatalf("Failed to read binary %d: %s", binary.ID, err)
		}
		contents = append(contents, content)
	}
	ids := map[int]int{}
	WithDatabaseKDBXVersion40()(db)
	for i, content := range contents {
		ids[db.Content.Meta.Binaries[i].ID] = db.AddBinary(content).ID
	}
	db.Content.Meta.Binaries = nil
	converted := findEntryByTitle(db.Content.Root.Groups, "attachments")
	for i := range converted.Binaries {
		converted.Binaries[i].Value.ID = ids[converted.Binaries[i].Value.ID]
	}
	assertAttachments(t, db)
	db = saveAndReopen(t, db)
	assertAttachments(t, db)

	// Copy the attachments into a KDBX 3.1 database, like merging databases does
	target := NewDatabase(WithDatabaseKDBXVersion3())
	target.Credentials = NewPasswordCredentials(password)
	copied := newAttachmentsEntry()
	for _, reference := range findEntryByTitle(db.Content.Root.Groups, "attachments").Binaries {
		content, err := db.FindBinary(reference.Value.ID).GetContentBytes()
		if err != nil {
			t.Fatalf("Failed to read attachment %q: %s", reference.Name, err)
		}
		binary := target.AddBinary(content)
		copied.Binaries = append(copied.Binaries, binary.CreateReference(reference.Name))
	}
	target.Content.Root.Groups[0].Entries = append(target.Content.Root.Groups[0].Entries, copied)
	assertAttachments(t, target)
	assertAttachments(t, saveAndReopen(t, target))
}
