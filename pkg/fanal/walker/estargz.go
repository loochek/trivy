package walker

import (
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

		if err := fn(p, &tocFileInfo{e: ent}, func() (xio.ReadSeekCloserAt, error) {
			return xio.NopCloser(fileSR), nil
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
