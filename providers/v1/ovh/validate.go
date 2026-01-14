package ovh

import (
	"context"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// Dynamically validate the Secret Store configuration.
//
// An HTTP request is sent to the provider to verify authorization.
func (cl *ovhClient) Validate() (esv1.ValidationResult, error) {
	_, err := cl.okmsClient.ListSecretV2(context.Background(), cl.okmsId, nil, nil)
	if err != nil {
		return esv1.ValidationResultError, err
	}
	return esv1.ValidationResultReady, nil
}
