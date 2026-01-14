package ovh

import (
	"context"
	"errors"
	"regexp"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
)

// GetAllSecret retrieves multiple secrets from the Secret Manager.
// You can optionally filter secrets by name using a regular expression.
// When path is set to "/" or left empty, the search starts from the Secret Manager root.
func (cl *ovhClient) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	// List Secret Manager secrets.
	secrets, err := getSecretsList(ctx, cl.okmsClient, cl.okmsId, ref.Path)
	if err != nil {
		return map[string][]byte{}, err
	}
	if len(secrets) == 0 {
		return map[string][]byte{}, errors.New("no secrets found in the secret manager")
	}

	// Compile the regular expression defined in ref.Name.RegExp, if present.
	var regex *regexp.Regexp

	if ref.Name != nil {
		regex, err = regexp.Compile(ref.Name.RegExp)
		if err != nil || regex == nil {
			return map[string][]byte{}, errors.New("failed to parse regexp")
		}
	}

	return filterSecretsListWithRegexp(ctx, cl, secrets, regex, ref)
}

// Retrieve secrets located under the specified path.
// If the path is omitted, all secrets from the Secret Manager are returned.
func getSecretsList(ctx context.Context, okmsClient OkmsClient, okmsId uuid.UUID, path *string) ([]string, error) {
	var formatPath string

	// if path ends with '/' (and is not "/"), returns an empty list.
	// Secrets are not supposed to begin with '/'.
	if path == nil || *path == "" {
		formatPath = ""
	} else if len(*path) > 1 &&
		(*path)[len(*path)-1] == '/' &&
		(*path)[len(*path)-2] == '/' {
		return []string{}, nil
	} else {
		formatPath = *path
	}

	// Ensure `formatPath` does not end with '/', otherwise, GetSecretsMetadata
	// will not be able to retrieve secrets as it should.
	if formatPath != "" && formatPath[len(formatPath)-1] == '/' {
		formatPath = formatPath[:len(formatPath)-1]
	}

	return recursivelyGetSecretsList(ctx, okmsClient, okmsId, formatPath)
}

// Recursively traverses the path to retrieve all secrets it contains.
//
// The recursion stops when the for loop finishes iterating over the list
// returned by GetSecretsMetadata, or when an error occurs.
//
// A recursive call is triggered whenever a key ends with '/'.
//
// Example:
// Given the secrets ["secret1", "path/secret", "path/to/secret"] stored in the
// Secret Manager, an initial call to recursivelyGetSecretsList with path="path"
// will cause GetSecretsMetadata to return ["secret", "to/"]
// (see Note below for details on this behavior).
//
// - "secret" is added to the local secret list.
// - "to/" triggers a recursive call with path="path/to".
//
// In the second call, GetSecretsMetadata returns ["secret"], which is added to
// the local list. Since no key ends with '/', the recursion stops and the list
// is returned and merged into the result of the first call.
//
// Note: OVH's SDK GetSecretsMetadata does not return full paths.
// It returns only the next element of the hierarchy, and adds a trailing '/'
// when the element is a directory (i.e., not the last component).
//
// Examples:
//
//	secret1 = "path/to/secret1"
//	secret2 = "path/secret2"
//	secret3 = "path/secrets/secret3"
//
// For the path "path", GetSecretsMetadata returns:
//
//	["to/", "secret2", "secrets/"]
func recursivelyGetSecretsList(ctx context.Context, okmsClient OkmsClient, okmsId uuid.UUID, path string) ([]string, error) {
	var secretsList []string
	var secrets *types.GetMetadataResponse
	var err error

	// Retrieve the list of KMS secrets for the given path.
	// If no path is provided, retrieve all existing secrets from KMS.
	if path != "" && path[0] == '/' {
		return []string{}, nil
	}
	secrets, err = okmsClient.GetSecretsMetadata(ctx, okmsId, path, true)
	if err != nil {
		return nil, err
	}
	if secrets == nil || secrets.Data == nil || secrets.Data.Keys == nil || len(*secrets.Data.Keys) == 0 {
		return nil, nil
	}
	for _, key := range *secrets.Data.Keys {
		if key != "" && key[0] != '/' {
			var toAppend []string

			if key[len(key)-1] == '/' {
				if path != "" {
					key = path + "/" + key[:len(key)-1]
				} else {
					key = key[:len(key)-1]
				}
				toAppend, err = recursivelyGetSecretsList(ctx, okmsClient, okmsId, key)
				if err != nil {
					return nil, err
				}
			} else {
				if path == "" {
					toAppend = []string{key}
				} else {
					toAppend = []string{path + "/" + key}
				}
			}
			secretsList = append(secretsList, toAppend...)
		}
	}

	return secretsList, nil
}

// Filter the list of secrets using a regular expression.
func filterSecretsListWithRegexp(ctx context.Context, cl *ovhClient, secrets []string, regex *regexp.Regexp, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	secretsDataMap := make(map[string][]byte)
	for _, secret := range secrets {
		// Insert the secret if no regex is provided;
		// otherwise, insert only matching secrets.
		if ref.Name == nil || (regex != nil && regex.MatchString(secret)) {
			secretToInsert, err := cl.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
				Key:                secret,
				ConversionStrategy: ref.ConversionStrategy,
				DecodingStrategy:   ref.DecodingStrategy,
			})
			if err != nil && !errors.Is(err, esv1.NoSecretErr) {
				return map[string][]byte{}, err
			}
			if !errors.Is(err, esv1.NoSecretErr) {
				secretsDataMap[secret] = secretToInsert
			}
		}
	}
	if len(secretsDataMap) == 0 {
		return map[string][]byte{}, errors.New("no secrets matched the regexp")
	}
	return secretsDataMap, nil
}
