package cyclonedxxml

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	fmt.Println("###################### ENCODE XML", s.Vulnerabilities)

	bom := cyclonedxhelpers.ToFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(output, cyclonedx.BOMFileFormatXML)
	enc.SetPretty(true)

	err := enc.Encode(bom)
	return err
}
