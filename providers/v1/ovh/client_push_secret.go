package ovh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"

	corev1 "k8s.io/api/core/v1"
)

// Create or update a secret.
//
// If updatePolicy is set to Replace, the secret will be written, possibly overwriting an existing secret.
// If set to IfNotExists, it will not overwrite an existing secret.
func (cl *ovhClient) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	if secret == nil {
		return errors.New("nil secret")
	}
	if len(secret.Data) == 0 {
		return errors.New("cannot push empty secret")
	}

	// Check if the secret already exists.
	// This determines which method to use: create or update.
	remoteSecret, currentVersion, err := getSecretWithOvhSDK(ctx, cl.okmsClient, cl.okmsId, esv1.ExternalSecretDataRemoteRef{
		Key: data.GetRemoteKey(),
	})
	if err != nil && !errors.Is(err, esv1.NoSecretErr) {
		return err
	}
	secretExists := !errors.Is(err, esv1.NoSecretErr)

	// Build the secret to be pushed.
	secretToPush, err := buildSecretToPush(secret, data)
	if err != nil {
		return err
	}

	// Compare the data of secretToPush with that of remoteSecret.
	equal, err := compareSecretsData(secretToPush, remoteSecret)
	if err != nil {
		return err
	}
	if equal {
		return nil
	}

	// Set cas according to client configuration
	if !cl.cas {
		currentVersion = nil
	}

	// Push the secret.
	return pushNewSecret(
		ctx,
		cl.okmsClient,
		cl.okmsId,
		secretToPush,
		data.GetRemoteKey(),
		currentVersion,
		secretExists)
}

// Compare the secret to push with the remote secret.
// If they are equal, do not push the secret.
func compareSecretsData(secretToPush map[string]any, remoteSecret []byte) (bool, error) {
	if len(remoteSecret) == 0 {
		return false, nil
	}

	secretToPushByte, err := json.Marshal(secretToPush)
	if err != nil {
		return false, err
	}

	return bytes.Equal(secretToPushByte, remoteSecret), nil
}

// Build the secret to be pushed.
//
// If remoteProperty is defined, it will be used as the key to store the secret value.
// If secretKey is not defined, the entire secret value will be pushed.
// Otherwise, only the value of the specified secretKey will be pushed.
func buildSecretToPush(secret *corev1.Secret, data esv1.PushSecretData) (map[string]any, error) {
	// Retrieve the secret value to push based on secretKey.
	secretValueToPush := make(map[string]any)
	if data.GetSecretKey() == "" {
		for key, value := range secret.Data {
			var decoded any
			if err := json.Unmarshal(value, &decoded); err != nil {
				secretValueToPush[key] = string(value)
				continue
			}
			cleanJSON, err := json.Marshal(decoded)
			if err != nil {
				return map[string]any{}, err
			}

			secretValueToPush[key] = json.RawMessage(cleanJSON)
		}
	} else {
		var decoded any
		if err := json.Unmarshal(secret.Data[data.GetSecretKey()], &decoded); err != nil {
			secretValueToPush[data.GetSecretKey()] = string(secret.Data[data.GetSecretKey()])
		} else {
			secretValueToPush[data.GetSecretKey()] = json.RawMessage(secret.Data[data.GetSecretKey()])
		}
	}

	// Build the secret to push using remoteProperty.
	secretToPush := make(map[string]any)
	if data.GetProperty() == "" {
		secretToPush = secretValueToPush
	} else {
		secretToPush[data.GetProperty()] = secretValueToPush
	}

	return secretToPush, nil
}

// This pushes the created/updated secret.
func pushNewSecret(ctx context.Context, okmsClient OkmsClient, okmsId uuid.UUID, secretToPush map[string]any, path string, cas *uint32, secretExists bool) error {
	var err error

	if !secretExists {
		// Create a secret.
		_, err = okmsClient.PostSecretV2(ctx, okmsId, types.PostSecretV2Request{
			Path: path,
			Version: types.SecretV2VersionShort{
				Data: &secretToPush,
			},
		})
	} else {
		// Update a secret.
		_, err = okmsClient.PutSecretV2(ctx, okmsId, path, cas, types.PutSecretV2Request{
			Version: &types.SecretV2VersionShort{
				Data: &secretToPush,
			},
		})
	}

	return err
}
