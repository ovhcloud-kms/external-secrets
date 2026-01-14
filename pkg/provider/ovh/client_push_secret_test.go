package ovh

import (
	"context"
	"testing"

	"github.com/external-secrets/external-secrets/pkg/provider/ovh/fake"
	testingfake "github.com/external-secrets/external-secrets/pkg/provider/testing/fake"
	v1 "k8s.io/api/core/v1"
)

func TestPushSecret(t *testing.T) {
	testCases := map[string]struct {
		should string
		secret *v1.Secret
		data   testingfake.PushSecretData
	}{
		"Nil Secret": {
			should: "nil secret",
			secret: nil,
			data: testingfake.PushSecretData{
				SecretKey: "secretKey",
				RemoteKey: "remoteKey",
				Property:  "property",
			},
		},
		"Nil Secret Data": {
			should: "cannot push empty secret",
			secret: &v1.Secret{
				Data: nil,
			},
			data: testingfake.PushSecretData{
				SecretKey: "secretKey",
				RemoteKey: "remoteKey",
				Property:  "property",
			},
		},
		"Empty Secret Data": {
			should: "cannot push empty secret",
			secret: &v1.Secret{
				Data: map[string][]byte{},
			},
			data: testingfake.PushSecretData{
				SecretKey: "secretKey",
				RemoteKey: "remoteKey",
				Property:  "property",
			},
		},
		"Empty Remote Key": {
			should: "spec.data.remoteRef.key cannot be empty",
			secret: &v1.Secret{
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			data: testingfake.PushSecretData{
				RemoteKey: "",
			},
		},
		"Empty Secret Key / Empty Property / Existing Remote Key (Equal Data)": {
			should: "",
			secret: &v1.Secret{
				Data: map[string][]byte{
					"test4": []byte(`"value4"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "pattern2/test/test-secret",
				Property:  "",
			},
		},
		"Empty Secret Key / Property / Existing Remote Key (Equal Data)": {
			should: `{"property":{"test4":"value4"}}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"test4": []byte(`"value4"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "pattern2/test/test-secret",
				Property:  "property",
			},
		},
		"Empty Secret Key / Empty Property / Existing Remote Key (Non-Equal Data)": {
			should: `{"new-test4":"new-value4"}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"new-test4": []byte(`"new-value4"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "pattern2/test/test-secret",
				Property:  "",
			},
		},
		"Empty Secret Key / Property / Existing Remote Key (Non-Equal Data)": {
			should: `{"property":{"new-test4":"new-value4"}}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"new-test4": []byte(`"new-value4"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "pattern2/test/test-secret",
				Property:  "property",
			},
		},
		"Empty Secret Key / Empty Property / Non-Existent Remote Key": {
			should: `{"root":{"sub1":{"value":"string"},"sub2":"Name"},"test":"value","test1":"value1"}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "non-existent",
				Property:  "",
			},
		},
		"Empty Secret Key / Property / Non-Existent Remote Key": {
			should: `{"property":{"root":{"sub1":{"value":"string"},"sub2":"Name"},"test":"value","test1":"value1"}}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "",
				RemoteKey: "non-existent",
				Property:  "property",
			},
		},
		"Secret Key / Empty Property / Existing Remote Key": {
			should: `{"test":"value"}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "test",
				RemoteKey: "pattern1/path3",
				Property:  "",
			},
		},
		"Secret Key / Property / Existing Remote Key": {
			should: `{"property":{"test":"value"}}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "test",
				RemoteKey: "pattern1/path3",
				Property:  "property",
			},
		},
		"Secret Key / Property / Non-Existent Remote Key": {
			should: `{"property":{"test":"value"}}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "test",
				RemoteKey: "non-existent",
				Property:  "property",
			},
		},
		"Secret Key / Empty Property / Non-Existent Remote Key": {
			should: `{"test":"value"}`,
			secret: &v1.Secret{
				Data: map[string][]byte{
					"root":  []byte(`{"sub1":{"value":"string"},"sub2":"Name"}`),
					"test":  []byte(`"value"`),
					"test1": []byte(`"value1"`),
				},
			},
			data: testingfake.PushSecretData{
				SecretKey: "test",
				RemoteKey: "non-existent",
				Property:  "",
			},
		},
	}

	ctx := context.Background()
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cl := ovhClient{
				okmsClient: &fake.FakeOkmsClient{
					TestCase: name,
				},
			}
			err := cl.PushSecret(ctx, testCase.secret, testCase.data)
			if err != nil && testCase.should != err.Error() {
				t.Error()
			} else if err == nil && testCase.should != "" {
				t.Error()
			}
		})
	}
}
