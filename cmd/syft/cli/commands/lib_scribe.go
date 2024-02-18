package commands

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type PackagesOptions = packagesOptions

func DefaultPackagesOptions() *PackagesOptions {
	return defaultPackagesOptions()
}

func GetSource(opts *options.Catalog, userInput string, filters ...func(*source.Detection) error) (source.Source, error) {
	return getSource(opts, userInput, filters...)
}

func GenerateSBOM(id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	return generateSBOM(id, src, opts)
}
