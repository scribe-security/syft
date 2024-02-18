package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/pkg"
)

func EncodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	return helpers.EncodeLicenses(p)
}

func EncodeComponent(p pkg.Package) cyclonedx.Component {
	return helpers.EncodeComponent(p)
}

func EncodeAuthor(p pkg.Package) string {
	return helpers.EncodeAuthor(p)
}

func EncodePublisher(p pkg.Package) string {
	return helpers.EncodePublisher(p)
}
