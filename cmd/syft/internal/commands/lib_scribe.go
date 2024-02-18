package commands

import (
	"context"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type OptionsCatalog = options.Catalog
type ScanOptions = scanOptions

func GetSource(opts *options.Catalog, userInput string, filters ...func(*source.Detection) error) (source.Source, error) {
	return getSource(opts, userInput, filters...)
}

func GenerateSBOM(ctx context.Context, id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	return generateSBOM(ctx, id, src, opts)
}

func DefaultScanOptions() *scanOptions {
	return defaultScanOptions()
}
