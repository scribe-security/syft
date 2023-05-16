package syftjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/formats/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {

	fmt.Println("######## SYFTJSON  DECODER")
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode syft-json: %w", err)
	}

	return toSyftModel(doc)
}
