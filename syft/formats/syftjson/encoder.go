package syftjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	fmt.Println("############# SYFT JSON", s.Vulnerabilities)
	doc := ToFormatModel(s)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
