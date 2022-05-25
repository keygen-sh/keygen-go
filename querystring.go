package keygen

type querystring struct {
	Constraint string `url:"constraint,omitempty"`
	Channel    string `url:"channel,omitempty"`
	Limit      int    `url:"limit,omitempty"`
	Encrypt    bool   `url:"encrypt,omitempty"`
	Include    string `url:"include,omitempty"`
}
