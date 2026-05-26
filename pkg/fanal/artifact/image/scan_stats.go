package image

import (
	"encoding/json"
	"io/fs"
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// FileStat describes a single file encountered while walking a layer.
type FileStat struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// LayerStat describes one image layer and the files seen during its analysis.
// When Cached is true, the layer result was read from cache and Files is empty.
type LayerStat struct {
	DiffID string     `json:"diff_id"`
	Cached bool       `json:"cached"`
	Files  []FileStat `json:"files,omitempty"`
}

// ScanStats is the top-level structure written to the --stats-file JSON output.
type ScanStats struct {
	Image  string      `json:"image"`
	Layers []LayerStat `json:"layers"`
}

// inspectLayerResult is passed from each parallel layer task back to the
// pipeline's onResult callback.
type inspectLayerResult struct {
	os   types.OS
	stat LayerStat
}

func fileType(info os.FileInfo) string {
	m := info.Mode()
	switch {
	case m.IsRegular():
		return "regular"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeDevice != 0 && m&fs.ModeCharDevice != 0:
		return "chardev"
	case m&fs.ModeDevice != 0:
		return "blockdev"
	default:
		return "other"
	}
}

func writeScanStats(path string, stats ScanStats) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(stats)
}
