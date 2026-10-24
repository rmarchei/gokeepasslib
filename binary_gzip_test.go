package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"slices"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// truncatedContent returns the content which SetContent produced for a
// compressed binary before it closed the base64 encoder, which dropped the
// last one or two bytes of the gzip trailer unless the length of the gzip
// stream is a multiple of 3
func truncatedContent(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(base64.NewEncoder(base64.StdEncoding, &buf))
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("Failed to compress content: %s", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to compress content: %s", err)
	}

	return buf.Bytes()
}

// lostBytes returns the number of bytes of the gzip stream of data which the
// old writer dropped
func lostBytes(t *testing.T, data []byte) int {
	t.Helper()

	binary := Binary{}
	WithKDBXv31Binary(&binary)
	if err := binary.SetContent(data); err != nil {
		t.Fatalf("Failed to set content: %s", err)
	}
	complete, _ := base64.StdEncoding.DecodeString(string(binary.Content))
	truncated, _ := base64.StdEncoding.DecodeString(string(truncatedContent(t, data)))

	return len(complete) - len(truncated)
}

// payloadLosing returns a payload whose gzip stream lost the given number of
// bytes to the old writer
func payloadLosing(t *testing.T, lost int) []byte {
	t.Helper()

	for size := 1; size < 1000; size++ {
		payload := bytes.Repeat([]byte("x"), size)
		if lostBytes(t, payload) == lost {
			return payload
		}
	}
	t.Fatalf("Expected a payload whose gzip stream lost %d bytes", lost)
	return nil
}

var errDataAfterGzipStream = errors.New("data follows the gzip stream")

// readGzipStrictly decodes the content of a compressed binary like strict
// readers such as KeeWeb do: the gzip stream has to be complete, match its
// checksum and size and end with the content
func readGzipStrictly(content []byte) ([]byte, error) {
	stream, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(stream)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	gzipReader.Multistream(false)

	data, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}
	if reader.Len() > 0 {
		return nil, fmt.Errorf("%w: %d bytes", errDataAfterGzipStream, reader.Len())
	}

	return data, nil
}

// saveAndReopen locks and encodes db, unlocks it again and returns the saved
// database, decoded and unlocked
func saveAndReopen(t *testing.T, db *Database) *Database {
	t.Helper()

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Failed to lock entries: %s", err)
	}
	var buf bytes.Buffer
	if err := NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Failed to encode database: %s", err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock entries: %s", err)
	}

	reopened := NewDatabase()
	reopened.Credentials = db.Credentials
	if err := NewDecoder(&buf).Decode(reopened); err != nil {
		t.Fatalf("Failed to decode saved database: %s", err)
	}
	if err := reopened.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock saved database: %s", err)
	}

	return reopened
}

func TestBinarySetContentWritesCompleteGzipStream(t *testing.T) {
	random := rand.NewChaCha8([32]byte{})

	larger := []int{4096, 65537, 1 << 20}
	payloads := make([][]byte, 0, 2*301+len(larger))
	for size := range 301 {
		payload := make([]byte, size)
		random.Read(payload)
		payloads = append(payloads, bytes.Repeat([]byte("x"), size), payload)
	}
	for _, size := range larger {
		payload := make([]byte, size)
		random.Read(payload)
		payloads = append(payloads, payload)
	}

	for _, payload := range payloads {
		binary := NewDatabase(WithDatabaseKDBXVersion3()).AddBinary(payload)

		data, err := readGzipStrictly(binary.Content)
		if err != nil {
			t.Fatalf("Content of %d bytes: invalid gzip stream: %s", len(payload), err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatalf("Content of %d bytes: received %d different bytes", len(payload), len(data))
		}
	}
}

// assertCompleteBinaries checks that the binaries are identical to the given
// contents written by SetContent and hold the payloads in valid gzip streams
func assertCompleteBinaries(t *testing.T, bs Binaries, contents, payloads [][]byte) {
	t.Helper()

	if len(bs) != len(contents) {
		t.Fatalf("Expected %d binaries, received %d", len(contents), len(bs))
	}
	for i := range bs {
		if !bytes.Equal(bs[i].Content, contents[i]) {
			t.Errorf(
				"Binary %d: expected the %d bytes written by SetContent, received %d other bytes",
				i, len(contents[i]), len(bs[i].Content),
			)
		}
		data, err := readGzipStrictly(bs[i].Content)
		if err != nil {
			t.Errorf("Binary %d: invalid gzip stream: %s", i, err)
		} else if !bytes.Equal(data, payloads[i]) {
			t.Errorf("Binary %d: expected %d bytes, received %d other bytes",
				i, len(payloads[i]), len(data))
		}
	}
}

func TestEncodeCompletesTruncatedGzipTrailers(t *testing.T) {
	// The old writer dropped as many bytes as the gzip stream is longer than
	// a multiple of 3. The length depends on the compressor of the Go version,
	// so payloads are added until streams which lost two, one and no bytes are
	// included. Streams which lost bytes have to be completed, while complete
	// ones have to stay as they are
	payloads := make([][]byte, 0, 16)
	lost := map[int]bool{}
	for size := 0; size < 12 || (len(lost) < 3 && size < 1000); size++ {
		payload := bytes.Repeat([]byte("x"), size)
		payloads = append(payloads, payload)
		lost[lostBytes(t, payload)] = true
	}
	if len(lost) < 3 {
		t.Fatalf("Expected streams which lost two, one and no bytes, received %v", lost)
	}
	random := rand.NewChaCha8([32]byte{1})
	for _, size := range []int{100, 1000, 70000} {
		payload := make([]byte, size)
		random.Read(payload)
		payloads = append(payloads, payload)
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
			// A database written before SetContent closed the base64 encoder
			db := NewDatabase(version.option)
			db.Credentials = NewPasswordCredentials(password)
			entry := NewEntry()
			contents := make([][]byte, len(payloads))
			for i, payload := range payloads {
				binary := Binary{ID: i}
				WithKDBXv31Binary(&binary)
				if err := binary.SetContent(payload); err != nil {
					t.Fatalf("Failed to set content: %s", err)
				}
				contents[i] = binary.Content
				binary.Content = truncatedContent(t, payload)
				db.Content.Meta.Binaries = append(db.Content.Meta.Binaries, binary)
				reference := binary.CreateReference(fmt.Sprintf("%d.bin", i))
				entry.Binaries = append(entry.Binaries, reference)
			}
			db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

			for range 2 {
				reopened := saveAndReopen(t, db)
				assertCompleteBinaries(t, db.Content.Meta.Binaries, contents, payloads)
				assertCompleteBinaries(t, reopened.Content.Meta.Binaries, contents, payloads)
				db = reopened
			}
		})
	}
}

func TestEncodeCompletesGzipTrailersOnlyLackingTheSize(t *testing.T) {
	payload := make([]byte, 802)
	rand.NewChaCha8([32]byte{2}).Read(payload)

	// stream returns a gzip stream which is a multiple of 3 bytes long without
	// its last cut bytes, so that the content of the cut stream is not padded,
	// like the content truncated by the old writer. Its stored blocks keep the
	// deflate data valid when a byte of the payload is changed, and its content
	// is longer than 1024 characters
	stream := func(cut int) []byte {
		t.Helper()

		for size := 800; ; size++ {
			var buf bytes.Buffer
			writer, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
			if err != nil {
				t.Fatalf("Failed to create gzip writer: %s", err)
			}
			if _, err := writer.Write(payload[:size]); err != nil {
				t.Fatalf("Failed to compress content: %s", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Failed to compress content: %s", err)
			}
			if (buf.Len()-cut)%3 == 0 {
				return buf.Bytes()
			}
		}
	}
	encode := func(stream []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(stream))
	}

	// content returns stream(cut) without its last cut bytes, with the byte at
	// offset inverted unless it is 0. A negative offset counts from the end of
	// the stream, which ends with the CRC-32 and the size of 4 bytes each
	content := func(cut, offset int) []byte {
		complete := stream(cut)
		changed := bytes.Clone(complete[:len(complete)-cut])
		if offset < 0 {
			offset += len(complete)
		}
		if offset > 0 {
			changed[offset] ^= 0xff
		}
		return encode(changed)
	}
	compressed := func(content []byte) Binary {
		return Binary{Content: content, Compressed: w.NewBoolWrapper(true)}
	}
	whole := stream(0)
	complete := encode(whole)
	protected := w.NewBoolWrapper(true)

	// stream(1) lacking 2 bytes of its size, whose first 767 bytes are encoded
	// on their own: they end with padding at character 1024, while the rest is
	// a multiple of 3 bytes long and is not padded
	split := stream(1)
	split = split[:len(split)-2]
	paddedWithin := slices.Concat(encode(split[:767]), encode(split[767:]))

	// A gzip header, a stored block which is not the final one and a block of
	// the reserved type, followed by the CRC-32 of the stored data and a size
	// lacking 2 bytes: the CRC-32 matches the data decompressed before the
	// deflate data turns out to be invalid
	corrupt := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 0, 2, 0, 0xfd, 0xff, 'a', 'b', 0x07}
	corrupt = binary.LittleEndian.AppendUint32(corrupt, crc32.ChecksumIEEE([]byte("ab")))
	corrupt = append(corrupt, 2, 0)

	cases := []struct {
		title    string
		binary   Binary
		expected []byte
	}{
		{title: "complete stream", binary: compressed(complete)},
		{
			// Complete streams are not encoded again
			title:  "complete stream with a line break",
			binary: compressed(slices.Concat(complete[:76], []byte("\n"), complete[76:])),
		},
		{title: "size lacks 1 byte", binary: compressed(content(1, 0)), expected: encode(stream(1))},
		{title: "size lacks 2 bytes", binary: compressed(content(2, 0)), expected: encode(stream(2))},
		{title: "size lacks 3 bytes", binary: compressed(content(3, 0)), expected: encode(stream(3))},
		{title: "size is missing", binary: compressed(content(4, 0)), expected: encode(stream(4))},
		{
			// Decoders skip line breaks, so the missing bytes are appended
			// after them
			title:  "size lacks 2 bytes, followed by a line break",
			binary: compressed(slices.Concat(content(2, 0), []byte("\r\n"))),
			expected: slices.Concat(
				content(2, 0), []byte("\r\n"), encode(stream(2))[len(content(2, 0)):],
			),
		},
		{
			// The old writer never padded the content it truncated, so padded
			// content is not even decoded
			title:  "padded content whose size lacks 1 byte",
			binary: compressed(encode(whole[:len(whole)-1])),
		},
		{
			// The missing bytes would follow the padding after the line break,
			// which is invalid base64
			title:  "padded content with a line break whose size lacks 1 byte",
			binary: compressed(slices.Concat(encode(whole[:len(whole)-1]), []byte("\n"))),
		},
		{
			title:  "padded content with CRLF whose size lacks 1 byte",
			binary: compressed(slices.Concat(encode(whole[:len(whole)-1]), []byte("\r\n"))),
		},
		{
			// Content padded before its end is invalid base64, but the decoder
			// of the check decodes blocks of up to 1024 characters on their own
			// and accepts padding at the end of each of them
			title:  "content padded before its end whose size lacks 2 bytes",
			binary: compressed(paddedWithin),
		},
		{title: "CRC-32 is truncated", binary: compressed(content(5, 0))},
		{title: "trailer is missing", binary: compressed(content(8, 0))},
		{title: "deflate data lacks 1 byte", binary: compressed(content(9, 0))},
		{title: "deflate data is truncated", binary: compressed(content(150, 0))},
		{title: "deflate data is invalid", binary: compressed(encode(corrupt))},
		{title: "CRC-32 is mismatching", binary: compressed(content(2, -8))},
		{title: "payload is mismatching", binary: compressed(content(2, 20))},
		{title: "size is mismatching", binary: compressed(content(1, -4))},
		{title: "complete stream with a mismatching CRC-32", binary: compressed(content(0, -8))},
		{
			// A stream which is a multiple of 3 bytes long with one more byte
			title:  "data follows the stream",
			binary: compressed(encode(append(bytes.Clone(stream(-1)), 0x00))),
		},
		{
			title:  "invalid base64 follows the stream",
			binary: compressed(slices.Concat(content(2, 0), []byte("QQ"))),
		},
		{title: "header is truncated", binary: compressed(encode(whole[:6]))},
		{title: "no gzip stream", binary: compressed([]byte("SGVsbG8h"))},
		{title: "no base64", binary: compressed([]byte("this is not base64!"))},
		{title: "empty", binary: compressed(nil)},
		{
			// Attachments which are truncated gzip files have to stay as they are
			title:  "uncompressed binary",
			binary: Binary{Content: content(2, 0)},
		},
		{
			// KeePass ignores the Compressed flag of a protected binary
			title: "protected binary",
			binary: Binary{
				Content:    content(2, 0),
				Compressed: w.NewBoolWrapper(true),
				Protected:  &protected,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			expected := c.expected
			if expected == nil {
				expected = c.binary.Content
			}

			db := NewDatabase(WithDatabaseKDBXVersion3())
			db.Credentials = NewPasswordCredentials(password)
			db.Content.Meta.Binaries = Binaries{c.binary}
			entry := NewEntry()
			entry.Binaries = append(entry.Binaries, c.binary.CreateReference("a.bin"))
			db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

			reopened := saveAndReopen(t, db)
			for _, current := range []*Database{db, reopened} {
				binaries := current.Content.Meta.Binaries
				if len(binaries) != 1 {
					t.Fatalf("Expected 1 binary, received %d", len(binaries))
				}
				if !bytes.Equal(binaries[0].Content, expected) {
					t.Errorf("Expected content %s, received %s", expected, binaries[0].Content)
				}
			}
		})
	}
}

func TestEncodeCompletesTruncatedGzipTrailersWithProtectedBinary(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx3/protected-binary.kdbx", interopPassword)
	if len(db.Content.Meta.Binaries) != 1 || !db.Content.Meta.Binaries[0].isStreamProtected() {
		t.Fatal("Expected a single protected meta binary")
	}

	// Binaries which lost one and two bytes of their gzip streams before and
	// after the protected one, which consumes the inner stream before every
	// protected value of the entries
	payloads := [][]byte{payloadLosing(t, 1), payloadLosing(t, 2)}
	binaries := make([]Binary, len(payloads))
	contents := make([][]byte, len(payloads))
	entry := findEntryByTitle(db.Content.Root.Groups, "e4-root")
	for i, payload := range payloads {
		binaries[i] = Binary{ID: i + 1, Compressed: w.NewBoolWrapper(true)}
		if err := binaries[i].SetContent(payload); err != nil {
			t.Fatalf("Failed to set content: %s", err)
		}
		contents[i] = binaries[i].Content
		binaries[i].Content = truncatedContent(t, payload)
		entry.Binaries = append(entry.Binaries, binaries[i].CreateReference(fmt.Sprintf("%d.bin", i)))
	}
	db.Content.Meta.Binaries = Binaries{binaries[0], db.Content.Meta.Binaries[0], binaries[1]}

	for range 2 {
		reopened := saveAndReopen(t, db)
		for _, current := range []*Database{db, reopened} {
			assertInteropContent(t, current)

			e2 := findEntryByTitle(current.Content.Root.Groups, "e2-in-g1")
			protectedBinary := current.FindBinary(e2.Binaries[0].Value.ID)
			if protectedBinary == nil || !protectedBinary.isStreamProtected() {
				t.Fatal("Expected the attachment of e2-in-g1 to stay a protected binary")
			}
			data, err := protectedBinary.GetContentBytes()
			if err != nil {
				t.Fatalf("Failed to read protected binary: %s", err)
			}
			if want := bytes.Repeat([]byte{0x07}, 16); !bytes.Equal(data, want) {
				t.Errorf("Protected binary: expected % x, received % x", want, data)
			}

			e4 := findEntryByTitle(current.Content.Root.Groups, "e4-root")
			repaired := Binaries{}
			for _, ref := range e4.Binaries {
				binary := current.FindBinary(ref.Value.ID)
				if binary == nil {
					t.Fatalf("Binary of attachment %q not found", ref.Name)
				}
				repaired = append(repaired, *binary)
			}
			assertCompleteBinaries(t, repaired, contents, payloads)
		}
		db = reopened
	}
}
