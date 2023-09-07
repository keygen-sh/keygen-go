package keygen

type querystring struct {
	Constraint string `url:"constraint,omitempty"`
	Channel    string `url:"channel,omitempty"`
	Product    string `url:"product,omitempty"`
	Package    string `url:"package,omitempty"`
	Limit      int    `url:"limit,omitempty"`
}
