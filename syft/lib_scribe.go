package syft

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/syft/source"
)

// GetSource uses all of Syft's known source providers to attempt to resolve the user input to a usable source.Source
func GetSourceWithProviderName(ctx context.Context, userInput string, cfg *GetSourceConfig) (source.Source, string, error) {
	if cfg == nil {
		cfg = DefaultGetSourceConfig()
	}

	providers, err := cfg.getProviders(userInput)
	if err != nil {
		return nil, "", err
	}
	var errs []error
	var fileNotFoundProviders []string

	// call each source provider until we find a valid source
	for _, p := range providers {
		src, err := p.Provide(ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fileNotFoundProviders = append(fileNotFoundProviders, p.Name())
			} else {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			}
		}
		if src != nil {
			// if we have a non-image type and platform is specified, it's an error
			if cfg.SourceProviderConfig.Platform != nil {
				meta := src.Describe().Metadata
				switch meta.(type) {
				case *source.ImageMetadata, source.ImageMetadata:
				default:
					return src, "", fmt.Errorf("platform specified with non-image source")
				}
			}
			return src, p.Name(), nil
		}
	}

	if len(fileNotFoundProviders) > 0 {
		errs = append(errs, fmt.Errorf("additionally, the following providers failed with %w: %s", os.ErrNotExist, strings.Join(fileNotFoundProviders, ", ")))
	}
	return nil, "", sourceError(userInput, errs...)
}
