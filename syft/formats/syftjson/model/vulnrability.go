package model

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Vulnerability struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      pkg.Type          `json:"type"`
	FoundBy   string            `json:"foundBy"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  pkg.Language      `json:"language"`
	CPEs      []string          `json:"cpes"`
	PURL      string            `json:"purl"`
}
