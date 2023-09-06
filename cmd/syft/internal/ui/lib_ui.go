package ui

import (
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
)

func NewlibUI() UI {
	return &libUI{}
}

type libUI struct {
	unsubscribe func() error
}

func (h *libUI) Setup(unsubscribe func() error) error {
	h.unsubscribe = unsubscribe
	return nil
}

func (h *libUI) Handle(event partybus.Event) error {
	// ctx := context.Background()
	switch {
	case event.Type == syftEvent.Exit:
		// this is the last expected event, stop listening to events
		return h.unsubscribe()
	default:
		return nil
	}
}

func (h *libUI) Teardown(force bool) error {
	return nil
}
