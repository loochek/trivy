package walker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/containerd/stargz-snapshotter/estargz"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// WalkEStargz opens an eStargz-formatted layer and calls fn for each regular
// file where required(path, info) returns true. Files are fetched via HTTP
// Range requests using the eStargz TOC, so only needed files are downloaded.
//
// The SectionReader must cover the full compressed layer blob.
func WalkEStargz(sr *io.SectionReader, required func(string, os.FileInfo) bool, fn WalkFunc) error {
	jtoc, err := readTOC(sr)
	if err != nil {
		return err
	}

	r, err := estargz.Open(sr, estargz.WithDecompressors(new(estargz.GzipDecompressor)))
	if err != nil {
		return err
	}

	// TOC may contain multiple entries per file (chunk entries for large files);
	// process each file name exactly once.
	seen := make(map[string]bool, len(jtoc.Entries))
	for _, ent := range jtoc.Entries {
		if ent.Type != "reg" || seen[ent.Name] {
			continue
		}
		seen[ent.Name] = true

		info := &tocFileInfo{e: ent}
		if !required(ent.Name, info) {
			continue
		}

		fileSR, err := r.OpenFile(ent.Name)
		if err != nil {
			continue
		}

		// Read the entire decompressed file in one ReadAt call.
		// fileReader.ReadAt creates a fresh bufio.Reader (2 MB) and calls
		// Peek on every invocation — many small reads balloon bytes_fetched.
		// One large ReadAt lets the single bufio.Reader refill sequentially.
		data := make([]byte, ent.Size)
		n, readErr := fileSR.ReadAt(data, 0)
		data = data[:n]
		if readErr != nil && readErr != io.EOF {
			continue
		}

		if err := fn(ent.Name, info, func() (xio.ReadSeekCloserAt, error) {
			return xio.NopCloser(bytes.NewReader(data)), nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// readTOC fetches and parses the eStargz TOC from the layer blob.
// It uses only the public API: OpenFooter (for the TOC offset) and JTOC (the
// exported JSON type). The TOC is typically a few hundred KB and is fetched
// via a single HTTP Range request from the end of the blob.
func readTOC(sr *io.SectionReader) (*estargz.JTOC, error) {
	tocOffset, footerSize, err := estargz.OpenFooter(sr)
	if err != nil {
		return nil, fmt.Errorf("read eStargz footer: %w", err)
	}

	tocSize := sr.Size() - footerSize - tocOffset
	if tocSize <= 0 {
		return nil, fmt.Errorf("invalid TOC size %d (blob=%d footer=%d offset=%d)",
			tocSize, sr.Size(), footerSize, tocOffset)
	}

	tocBytes := make([]byte, tocSize)
	if _, err := sr.ReadAt(tocBytes, tocOffset); err != nil {
		return nil, fmt.Errorf("read TOC bytes: %w", err)
	}

	// TOC is stored as gzip(tar(stargz.index.json)) — not plain gzip+JSON.
	gr, err := gzip.NewReader(bytes.NewReader(tocBytes))
	if err != nil {
		return nil, fmt.Errorf("TOC gzip reader: %w", err)
	}
	gr.Multistream(false)
	defer gr.Close()

	tr := tar.NewReader(gr)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("TOC tar entry: %w", err)
	}
	if hdr.Name != estargz.TOCTarName {
		return nil, fmt.Errorf("unexpected TOC tar entry name %q, want %q", hdr.Name, estargz.TOCTarName)
	}

	var jtoc estargz.JTOC
	if err := json.NewDecoder(tr).Decode(&jtoc); err != nil {
		return nil, fmt.Errorf("decode TOC JSON: %w", err)
	}
	return &jtoc, nil
}

// tocFileInfo implements os.FileInfo from an eStargz TOCEntry.
type tocFileInfo struct {
	e *estargz.TOCEntry
}

func (t *tocFileInfo) Name() string       { return path.Base(t.e.Name) }
func (t *tocFileInfo) Size() int64        { return t.e.Size }
func (t *tocFileInfo) Mode() fs.FileMode  { return fs.FileMode(t.e.Mode) }
func (t *tocFileInfo) ModTime() time.Time { return t.e.ModTime() }
func (t *tocFileInfo) IsDir() bool        { return t.e.Type == "dir" }
func (t *tocFileInfo) Sys() any           { return nil }
