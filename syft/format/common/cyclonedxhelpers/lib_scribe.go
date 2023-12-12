package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func EncodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	return encodeLicenses(p)
}
