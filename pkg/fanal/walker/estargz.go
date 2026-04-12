package walker

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"time"

	"github.com/containerd/stargz-snapshotter/estargz"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// WalkEStargz opens an eStargz-formatted layer and calls fn for each file
// whose path is listed in staticPaths. The SectionReader must cover the full
// compressed layer blob. Returns an error if the blob is not valid eStargz.
func WalkEStargz(sr *io.SectionReader, staticPaths []string, fn WalkFunc) error {
	r, err := estargz.Open(sr, estargz.WithDecompressors(new(estargz.GzipDecompressor)))
	if err != nil {
		return err
	}

	for _, p := range staticPaths {
		ent, ok := r.Lookup(p)
		if !ok || ent.Type != "reg" {
			continue
		}

		fileSR, err := r.OpenFile(p)
		if err != nil {
			continue
		}

		// Buffer the decompressed file with a single ReadAt for the whole size.
		//
		// The eStargz fileReader.ReadAt creates a fresh bufio.Reader and calls
		// Peek(2MB) on every invocation, making one HTTP Range request per call
		// regardless of how many bytes are actually requested. io.ReadAll / io.Copy
		// translate to many small Read calls → many ReadAt calls → bytes_fetched
		// balloons to (num_reads × 2MB) >> layer_size.
		//
		// Calling ReadAt once with the full decompressed size means the single
		// bufio.Reader refills sequentially as it decompresses, so total HTTP
		// traffic ≈ compressed_file_size ≤ layer_size.
		data := make([]byte, ent.Size)
		n, readErr := fileSR.ReadAt(data, 0)
		data = data[:n]
		if readErr != nil && readErr != io.EOF {
			continue
		}

		if err := fn(p, &tocFileInfo{e: ent}, func() (xio.ReadSeekCloserAt, error) {
			return xio.NopCloser(bytes.NewReader(data)), nil
		}); err != nil {
			return err
		}
	}

	return nil
}

// tocFileInfo implements os.FileInfo from an eStargz TOCEntry.
type tocFileInfo struct {
	e *estargz.TOCEntry
}

func (t *tocFileInfo) Name() string      { return path.Base(t.e.Name) }
func (t *tocFileInfo) Size() int64       { return t.e.Size }
func (t *tocFileInfo) Mode() fs.FileMode { return fs.FileMode(t.e.Mode) }
func (t *tocFileInfo) ModTime() time.Time { return t.e.ModTime() }
func (t *tocFileInfo) IsDir() bool       { return t.e.Type == "dir" }
func (t *tocFileInfo) Sys() any          { return nil }
