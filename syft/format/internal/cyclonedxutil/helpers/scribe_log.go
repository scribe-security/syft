package helpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func EncodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	return encodeLicenses(p)
}

// func EncodeComponent(p pkg.Package) cyclonedx.Component {
// 	return encodeComponent(p)
// }

func EncodeAuthor(p pkg.Package) string {
	return encodeAuthor(p)
}

func EncodePublisher(p pkg.Package) string {
	return encodePublisher(p)
}
