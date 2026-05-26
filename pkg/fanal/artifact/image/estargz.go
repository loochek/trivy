package image

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync"
	"sync/atomic"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

// httpRangeReader implements io.ReaderAt by making HTTP Range requests against
// a registry blob endpoint. Bearer token negotiation is performed lazily on
// the first 401 response.
type httpRangeReader struct {
	url      string
	client   *http.Client
	mu       sync.Mutex
	token    string
	username string
	password string
	size     int64
	fetched  atomic.Int64
}

func newHTTPRangeReader(
	ctx context.Context,
	blobURL string,
	registryOpts types.RegistryOptions,
	size int64,
) *httpRangeReader {
	tr := xhttp.RoundTripper(ctx)
	var username, password string
	for _, cred := range registryOpts.Credentials {
		username = cred.Username
		password = cred.Password
		break
	}
	return &httpRangeReader{
		url:      blobURL,
		client:   &http.Client{Transport: tr},
		username: username,
		password: password,
		size:     size,
	}
}

func (r *httpRangeReader) ReadAt(p []byte, off int64) (int, error) {
	return r.doRead(p, off, true)
}

func (r *httpRangeReader) doRead(p []byte, off int64, retry bool) (int, error) {
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return 0, err
	}
	end := off + int64(len(p)) - 1
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, end))

	r.mu.Lock()
	tok := r.token
	r.mu.Unlock()
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized && retry {
		newTok, err := r.negotiateToken(resp)
		if err != nil {
			return 0, fmt.Errorf("bearer token negotiation: %w", err)
		}
		r.mu.Lock()
		r.token = newTok
		r.mu.Unlock()
		return r.doRead(p, off, false)
	}

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected HTTP %d for Range %d-%d", resp.StatusCode, off, end)
	}

	n, err := io.ReadFull(resp.Body, p)
	r.fetched.Add(int64(n))
	if err == io.ErrUnexpectedEOF {
		return n, io.EOF // last range is shorter — normal at EOF
	}
	return n, err
}

var bearerParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (r *httpRangeReader) negotiateToken(resp *http.Response) (string, error) {
	wwwAuth := resp.Header.Get("Www-Authenticate")
	params := make(map[string]string)
	for _, m := range bearerParamRe.FindAllStringSubmatch(wwwAuth, -1) {
		params[m[1]] = m[2]
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("no realm in Www-Authenticate: %q", wwwAuth)
	}

	req, err := http.NewRequest(http.MethodGet, realm, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}
	req.URL.RawQuery = q.Encode()
	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	tokenResp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer tokenResp.Body.Close()

	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Token != "" {
		return result.Token, nil
	}
	return result.AccessToken, nil
}

// BytesFetched returns the total number of bytes transferred from the registry.
func (r *httpRangeReader) BytesFetched() int64 {
	return r.fetched.Load()
}

// blobURL constructs the registry blob URL for the given layer.
// The image name is used to extract the registry host and repository path.
func blobURL(imageName string, layerDigest v1.Hash) (string, error) {
	ref, err := ggcrname.ParseReference(imageName, ggcrname.WeakValidation)
	if err != nil {
		return "", xerrors.Errorf("parse image ref %q: %w", imageName, err)
	}
	registry := ref.Context().RegistryStr()
	repo := ref.Context().RepositoryStr()
	return fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repo, layerDigest.String()), nil
}

// inspectLayerEStargz is an eStargz-aware variant of inspectLayer.
// Instead of downloading the full uncompressed layer, it uses HTTP Range
// requests to fetch only the files declared by StaticPathAnalyzers.
//
// Returns the BlobInfo and the number of bytes fetched from the registry.
// Returns a non-nil error if the layer is not eStargz or if static paths
// cannot be determined; the caller should fall back to inspectLayer.
func (a Artifact) inspectLayerEStargz(
	ctx context.Context,
	layer types.Layer,
	disabled []analyzer.Type,
) (types.BlobInfo, int64, LayerStat, error) {
	// Resolve the v1.Layer to get compressed digest and size.
	h, err := v1.NewHash(layer.DiffID)
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("invalid diff ID %s: %w", layer.DiffID, err)
	}
	v1Layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("get layer %s: %w", layer.DiffID, err)
	}
	compressedDigest, err := v1Layer.Digest()
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("layer digest: %w", err)
	}
	compressedSize, err := v1Layer.Size()
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("layer size: %w", err)
	}

	url, err := blobURL(a.image.Name(), compressedDigest)
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, err
	}

	rr := newHTTPRangeReader(ctx, url, a.artifactOption.ImageOption.RegistryOptions, compressedSize)
	sr := io.NewSectionReader(rr, 0, compressedSize)

	eg, egCtx := errgroup.WithContext(ctx)
	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)

	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	statsEnabled := a.artifactOption.StatsFile != ""
	var layerFiles []FileStat

	err = walker.WalkEStargz(sr, func(filePath string, info os.FileInfo) bool {
		requiredBy := a.analyzer.RequiredBy(filePath, info, disabled)
		if statsEnabled {
			layerFiles = append(layerFiles, FileStat{
				Name:       filePath,
				Size:       info.Size(),
				Type:       fileType(info),
				RequiredBy: requiredBy,
			})
		}
		return len(requiredBy) > 0
	}, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err := a.analyzer.AnalyzeFile(egCtx, eg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return xerrors.Errorf("analyze %s: %w", filePath, err)
		}

		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return xerrors.Errorf("copy to temp %s: %w", filePath, err)
		}
		if err = composite.CreateLink(analyzerTypes, "", filePath, tmpFilePath); err != nil {
			return xerrors.Errorf("create link %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("estargz walk: %w", err)
	}

	if err = eg.Wait(); err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("analyze: %w", err)
	}

	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("post analysis: %w", err)
	}

	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		// Size is the compressed layer size (bytes fetched, not full layer size)
		Size:      rr.BytesFetched(),
		Digest:    compressedDigest.String(),
		DiffID:    layer.DiffID,
		CreatedBy: layer.CreatedBy,
		// Whiteout detection is skipped in eStargz mode (only static paths are read).
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,
		BuildInfo:         result.BuildInfo,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, 0, LayerStat{}, xerrors.Errorf("post handler: %w", err)
	}

	fetched := rr.BytesFetched()
	a.logger.Debug("eStargz layer scan",
		log.String("diff_id", layer.DiffID),
		log.Int64("bytes_fetched", fetched),
		log.Int64("layer_size", compressedSize),
	)

	stat := LayerStat{DiffID: layer.DiffID, Files: layerFiles}
	return blobInfo, fetched, stat, nil
}
