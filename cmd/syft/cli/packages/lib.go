package packages

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

// func libInitBase(cfg *config.Application, l logger.Logger, enable_log, enable_ui bool) ([]ui.UI, error) {
// 	if err := cfg.LibParseConfigValues(); err != nil {
// 		return nil, fmt.Errorf("invalid application config: %w", err)
// 	}

// 	var uis []ui.UI
// 	uis = append(uis, ui.NewlibUI())

// 	if enable_log {
// 		if l == nil {
// 			newLogWrapper(cfg)
// 		} else {
// 			LibInitLoggingConfig(l)
// 		}
// 	}

// 	if enable_ui {
// 		uis = ui.Select(isVerbose(cfg), cfg.Quiet)
// 	}

// 	return uis, nil
// }

// func LibInitLoggingConfig(logWrapper logger.Logger) {
// 	syft.SetLogger(logWrapper)
// 	stereoscope.SetLogger(logWrapper)
// }

// func libInitEventBus() {
// 	if eventSubscription == nil {
// 		initEventBus()
// 	}
// }

// func LibPackagesExec(userInput string, cfg *config.Application, l logger.Logger, enable_log, enable_ui bool) (*sbom.SBOM, error) {

// 	uis, err := libInitBase(cfg, l, enable_log, enable_ui)
// 	if err != nil {
// 		return nil, err
// 	}

// 	libInitEventBus()
// 	outSbom, errs := packagesExecWorker(*si, cfg, writer)
// 	return sbomEventLoop(
// 		outSbom, errs,
// 		setupSignals(),
// 		eventSubscription,
// 		stereoscope.Cleanup,
// 		uis...,
// 	)
// }

func RunLib(ctx context.Context, app *config.Application, args []string) (*sbom.SBOM, error) {
	err := ValidateOutputOptions(app)
	if err != nil {
		return nil, err
	}

	writer, err := options.MakeWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// could be an image or a directory, with or without a scheme
	userInput := args[0]
	si, err := source.ParseInputWithName(userInput, app.Platform, app.Name, app.DefaultImagePullSource)
	if err != nil {
		return nil, fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	uis, err := libInitUI(app, false)
	if err != nil {
		return nil, err
	}

	sbom, errs := sbomExecWorker(app, *si, writer)
	return sbomEventLoop(
		sbom,
		errs,
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		uis...,
	)
}

func libInitUI(cfg *config.Application, enable_ui bool) ([]ui.UI, error) {
	if err := cfg.LibParseConfigValues(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	var uis []ui.UI
	uis = append(uis, ui.NewlibUI())

	if enable_ui {
		uis = ui.Select(options.IsVerbose(cfg), cfg.Quiet)
	}

	return uis, nil
}

func sbomExecWorker(app *config.Application, si source.Input, writer sbom.Writer) (chan *sbom.SBOM, <-chan error) {
	errs := make(chan error)
	outSbom := make(chan *sbom.SBOM, 1)

	go func() {
		defer close(errs)

		src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
			return
		}

		s, err := GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			errs <- fmt.Errorf("no SBOM produced for %q", si.UserInput)
		}

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(*s) },
		})

		if s != nil {
			outSbom <- s
		}
	}()
	return outSbom, errs
}

func sbomEventLoop(outSbom <-chan *sbom.SBOM, workerErrs <-chan error, signals <-chan os.Signal, subscription *partybus.Subscription, cleanupFn func(), uxs ...ui.UI) (*sbom.SBOM, error) {
	err := eventloop.EventLoop(workerErrs,
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
