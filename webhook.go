package keygen

import (
	"net/http"
)

// VerifyWebhook verifies the signature of a webhook request sent from
// Keygen. The webhook event should be considered invalid if an error
// is returned.
//
// Example:
//
//   func main() {
//       http.HandleFunc("/webhooks", func(w http.ResponseWriter, r *http.Request) {
//           if err := keygen.VerifyWebhook(r); err != nil {
//               w.WriteHeader(http.StatusBadRequest)
//
//               return
//           }
//
//           w.WriteHeader(http.StatusNoContent)
//       })
//
//       http.ListenAndServe(":8081", nil)
//   }
func VerifyWebhook(request *http.Request) error {
	verifier := &verifier{PublicKey: PublicKey}

	return verifier.VerifyRequest(request)
}
