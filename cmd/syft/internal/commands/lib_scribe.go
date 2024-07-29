package commands

import (
	"context"
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type OptionsCatalog = options.Catalog
type ScanOptions = scanOptions

// func GetSource(ctx context.Context, opts *options.Catalog, userInput string, sources ...string) (source.Source, error) {
// 	return getSource(ctx, opts, userInput, sources...)
// }

func GenerateSBOM(ctx context.Context, id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	return generateSBOM(ctx, id, src, opts)
}

func DefaultScanOptions() *scanOptions {
	return defaultScanOptions()
}

func GetSourceWithProviderName(ctx context.Context, opts *options.Catalog, userInput string, sources ...string) (source.Source, string, error) {
	cfg := syft.DefaultGetSourceConfig().
		WithRegistryOptions(opts.Registry.ToOptions()).
		WithAlias(source.Alias{
			Name:    opts.Source.Name,
			Version: opts.Source.Version,
		}).
		WithExcludeConfig(source.ExcludeConfig{
			Paths: opts.Exclusions,
		}).
		WithBasePath(opts.Source.BasePath).
		WithSources(sources...).
		WithDefaultImagePullSource(opts.Source.Image.DefaultPullSource)

	var err error
	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, "", fmt.Errorf("invalid platform: %w", err)
		}
		cfg = cfg.WithPlatform(platform)
	}

	if opts.Source.File.Digests != nil {
		hashers, err := file.Hashers(opts.Source.File.Digests...)
		if err != nil {
			return nil, "", fmt.Errorf("invalid hash algorithm: %w", err)
		}
		cfg = cfg.WithDigestAlgorithms(hashers...)
	}

	src, provider, err := syft.GetSourceWithProviderName(ctx, userInput, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("could not determine source: %w", err)
	}

	return src, provider, nil
}
