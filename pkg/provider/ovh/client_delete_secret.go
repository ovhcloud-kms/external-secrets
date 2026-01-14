package ovh

import (
	"context"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// If deletionPolicy is set to Delete, the Secret Manager Secret
// created from the Push Secret will be automatically removed
// when the associated Push Secret is deleted.
func (cl *ovhClient) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	err := cl.okmsClient.DeleteSecretV2(ctx, cl.okmsId, remoteRef.GetRemoteKey())
	return err
}
