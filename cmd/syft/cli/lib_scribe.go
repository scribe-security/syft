package cli

import (
	"bytes"
	"context"
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/internal/commands"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// type PackagesOptions = commands.PackagesOptions
type OptionsCatalog = commands.OptionsCatalog
type ScanOptions = commands.ScanOptions

func LibInitLoggingConfig(logWrapper logger.Logger) {
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper)
}

func DefaultScanOptions() *commands.ScanOptions {
	return commands.DefaultScanOptions()
}
func GetSourceWithProviderName(ctx context.Context, opts *options.Catalog, userInput string, sources ...string) (source.Source, string, error) {
	return commands.GetSourceWithProviderName(ctx, opts, userInput, sources...)
}

func GenerateSBOM(ctx context.Context, id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	return commands.GenerateSBOM(ctx, id, src, opts)
}

func LibPackagesExec(ctx context.Context, id clio.Identification, opts *ScanOptions, userInput string, l logger.Logger, enableLog bool, sources ...string) (*sbom.SBOM, string, error) {
	if enableLog {
		LibInitLoggingConfig(l)
	}

	src, provider, err := commands.GetSourceWithProviderName(ctx, &opts.Catalog, userInput, sources...)
	if err != nil {
		return nil, "", err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := commands.GenerateSBOM(ctx, id, src, &opts.Catalog)
	if err != nil {
		return nil, "", err
	}

	if s == nil {
		return nil, "", fmt.Errorf("no SBOM produced for %q", userInput)
	}

	return s, provider, nil

}

type SbomBuffer struct {
	Format sbom.FormatEncoder
	buf    *bytes.Buffer
}

func (w *SbomBuffer) Read() []byte {
	if w.buf != nil {
		return w.buf.Bytes()
	}

	return []byte{}
}

func (w *SbomBuffer) Write(s sbom.SBOM) error {
	if w.buf == nil {
		w.buf = &bytes.Buffer{}
	}
	if err := w.Format.Encode(w.buf, s); err != nil {
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}
	return nil
}
