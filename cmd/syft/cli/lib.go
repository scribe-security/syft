package cli

import (
	"context"
	"fmt"

	"github.com/anchore/go-logger"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
)

func libInitBase(cfg *config.Application, l logger.Logger, enable_log, enable_ui bool) error {
	if err := cfg.LibParseConfigValues(); err != nil {
		return fmt.Errorf("## invalid application config: %w", err)
	}

	// 	var uis []ui.UI
	// 	uis = append(uis, ui.NewlibUI())

	if enable_log {
		if l == nil {
			newLogWrapper(cfg)
		} else {
			LibInitLoggingConfig(l)
		}
	}

	// 	if enable_ui {
	// 		uis = ui.Select(options.IsVerbose(cfg), cfg.Quiet)
	// 	}

	// 	return uis, nil
	return nil
}

func LibInitLoggingConfig(logWrapper logger.Logger) {
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper)
}

// // func libInitEventBus() {
// // 	subscription := eventBus.Subscribe()
// // 	if subscription == nil {
// // 		initEventBus()
// // 	}
// // }

func LibPackagesExec(userInput string, cfg *config.Application, l logger.Logger, enable_log, enable_ui bool) (*sbom.SBOM, error) {
	err := libInitBase(cfg, l, enable_log, enable_ui)
	if err != nil {
		return nil, err
	}

	// 	libInitEventBus()
	return packages.RunLib(context.Background(), cfg, []string{userInput})
}
