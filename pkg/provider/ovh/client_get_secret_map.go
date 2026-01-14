package ovh

import (
	"context"
	"encoding/json"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/esutils"
)

// GetSecretMap retrieves a single secret from the provider.
// The created secret will have the same keys as the Secret Manager secret.
// You can specify a key, a property, and a version.
// If a property is provided, it should reference only nested values.
func (cl *ovhClient) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	// Retrieve secret from KMS.
	secretDataBytes, _, err := getSecretWithOvhSDK(ctx, cl.okmsClient, cl.okmsId, ref)
	if err != nil {
		return map[string][]byte{}, err
	}
	if len(secretDataBytes) == 0 {
		return map[string][]byte{}, nil
	}

	// Unmarshal the secret value into a map[string]any
	// so it can be passed to esutils.GetByteValueFromMap.
	var rawSecretDataMap map[string]any
	err = json.Unmarshal(secretDataBytes, &rawSecretDataMap)
	if err != nil {
		return map[string][]byte{}, err
	}

	// Convert the map[string]any into map[string][]byte.
	secretDataMap := make(map[string][]byte, len(rawSecretDataMap))
	for key := range rawSecretDataMap {
		secretDataMap[key], err = esutils.GetByteValueFromMap(rawSecretDataMap, key)
		if err != nil {
			return map[string][]byte{}, err
		}
	}

	return secretDataMap, nil
}
