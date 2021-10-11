package keygen

// Account is the Keygen account ID used globally in the binding.
var Account string

// Product is the Keygen product ID used globally in the binding.
var Product string

// Token is the Keygen API token used globally in the binding.
var Token string

func Validate() {
	c := client{account: Account, product: Product, token: Token}

	res, err := c.Post("licenses/actions/validate-key", nil)
	switch {
	case err != nil:
		//
	}

	defer res.Body.Close()
}

func Upgrade() {

}
