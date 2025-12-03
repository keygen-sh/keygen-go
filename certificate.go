package keygen

import "strings"

type certificate struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
	Alg string `json:"alg"`
}

func (c *certificate) EncodingAlgorithm() EncodingAlgorithm {
	alg := c.Alg[0:strings.Index(c.Alg, "+")]

	return EncodingAlgorithm(alg)
}

func (c *certificate) SigningAlgorithm() SigningAlgorithm {
	alg := c.Alg[strings.Index(c.Alg, "+")+1:]

	return SigningAlgorithm(alg)
}
