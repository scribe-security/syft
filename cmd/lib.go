package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/logger"
	syftLogger "github.com/anchore/syft/syft/logger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

func libInitBase(cfg *config.Application, l logger.Logger, enable_ui bool) ([]ui.UI, error) {
	if err := cfg.LibParseConfigValues(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	var uis []ui.UI
	uis = append(uis, ui.NewlibUI())
	if l == nil {
		initLoggingConfig(cfg)
	} else {
		libInitLoggingConfig(l)
	}

	if enable_ui {
		uis = ui.Select(isVerbose(cfg), cfg.Quiet)
	}

	return uis, nil
}

func libInitLoggingConfig(logWrapper syftLogger.Logger) {
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper)
}

func libInitEventBus() {
	if eventSubscription == nil {
		initEventBus()
	}
}

// LibPackagesExec run packages command as a library
// userInput: target
// cfg: syft configuration structure
// l: logger to attach to, nil  for default syft logger
// enable_ui: enable disable ui output
// Function return sbom or errors.
func LibPackagesExec(userInput string, cfg *config.Application, l logger.Logger, enable_ui bool) (*sbom.SBOM, error) {
	writer, err := makeWriter(cfg.Outputs, cfg.File)
	if err != nil {
		return nil, err
	}

	uis, err := libInitBase(cfg, l, enable_ui)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// could be an image or a directory, with or without a scheme
	si, err := source.ParseInput(userInput, cfg.Platform, true)
	if err != nil {
		return nil, fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	libInitEventBus()
	outSbom, errs := packagesExecWorker(*si, cfg, writer)
	return sbomEventLoop(
		outSbom, errs,
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		uis...,
	)
}

func sbomEventLoop(outSbom <-chan *sbom.SBOM, workerErrs <-chan error, signals <-chan os.Signal, subscription *partybus.Subscription, cleanupFn func(), uxs ...ui.UI) (*sbom.SBOM, error) {
	err := eventLoop(workerErrs,
		signals,
		subscription,
		cleanupFn,
		uxs...)

	var out *sbom.SBOM
	if err == nil {
		out = <-outSbom
	}

	return out, err

}
