package ovh

import (
	"context"
	"errors"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func (cl *ovhClient) SecretExists(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) (bool, error) {
	// Check if the secret exists using the OVH SDK.
	_, err := cl.okmsClient.GetSecretV2(ctx, cl.okmsId, remoteRef.GetRemoteKey(), nil, nil)
	if err != nil && errors.Is(handleOkmsError(err), esv1.NoSecretErr) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}
