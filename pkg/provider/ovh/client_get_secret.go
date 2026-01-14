package ovh

import (
	"context"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// GetSecret retrieves a single secret from the provider.
// The created secret will store the entire secret value under the specified key.
// You can specify a key, a property and a version.
func (cl *ovhClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	// Retrieve the KMS secret using the OVH SDK.
	secretData, _, err := getSecretWithOvhSDK(ctx, cl.okmsClient, cl.okmsId, ref)
	if err != nil {
		return []byte{}, err
	}

	return secretData, nil
}
