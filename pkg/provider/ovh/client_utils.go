package ovh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/tidwall/gjson"
)

func getSecretWithOvhSDK(ctx context.Context, kmsClient OkmsClient, okmsId uuid.UUID, ref esv1.ExternalSecretDataRemoteRef) ([]byte, *uint32, error) {
	// Check if the remoteRef key is empty.
	if ref.Key == "" {
		return []byte{}, nil, errors.New("spec.data.remoteRef.key cannot be empty")
	}

	// Check MetaDataPolicy (not supported).
	if ref.MetadataPolicy == esv1.ExternalSecretMetadataPolicyFetch {
		return []byte{}, nil, errors.New("fetch metadata policy not supported")
	}

	// Decode the secret version.
	versionAddr, err := decodeSecretVersion(ref.Version)
	if err != nil {
		return []byte{}, nil, err
	}

	// Retrieve the KMS secret.
	includeData := true
	secret, err := kmsClient.GetSecretV2(ctx, okmsId, ref.Key, versionAddr, &includeData)
	if err != nil {
		return []byte{}, nil, handleOkmsError(err)
	}
	if secret == nil {
		return []byte{}, nil, esv1.NoSecretErr
	}

	// Retrieve KMS Secret property if needed.
	var secretData []byte

	if ref.Property == "" {
		secretData, err = json.Marshal(secret.Version.Data)
	} else {
		secretData, err = getPropertyValue(secret.Version.Data, ref.Property)
	}

	return secretData, secret.Metadata.CurrentVersion, err
}

// Decode a secret version.
//
// Returns nil if no version is provided; in that case, the OVH SDK uses the latest version.
func decodeSecretVersion(strVersion string) (*uint32, error) {
	var version *uint32

	if strVersion != "" {
		v, err := strconv.Atoi(strVersion)
		if err != nil {
			return version, err
		}
		tmpVersion := uint32(v)
		if int(tmpVersion) != v {
			return nil, errors.New("overflow occurred while decoding secret version")
		}
		version = &tmpVersion
	}
	return version, nil
}

// Retrieve the value of the secret property.
func getPropertyValue(data *map[string]any, property string) ([]byte, error) {
	// Marshal data into bytes so it can be passed to gjson.Get.
	secretData, err := json.Marshal(data)
	if err != nil {
		return []byte{}, err
	}

	// Retrieve the property value if it exists.
	secretDataResult := gjson.Get(string(secretData), property)
	if !secretDataResult.Exists() {
		return []byte{}, fmt.Errorf("secret property \"%s\" not found", property)
	}

	return []byte(secretDataResult.String()), nil
}

// Returns an okms.KmsError struct representing the KMS response
// (error_code, error_id, errors, request_id).
func handleOkmsError(err error) error {
	okmsError := okms.AsKmsError(err)

	if okmsError == nil {
		return fmt.Errorf("failed to parse okms error: %w", err)
	} else if okmsError.ErrorCode == 17125377 {
		return esv1.NoSecretErr
	}
	return okmsError
}
