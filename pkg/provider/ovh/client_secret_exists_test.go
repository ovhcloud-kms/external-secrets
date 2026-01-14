package ovh

import (
	"context"
	"testing"

	"github.com/external-secrets/external-secrets/pkg/provider/ovh/fake"
	testingfake "github.com/external-secrets/external-secrets/pkg/provider/testing/fake"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSecretExists(t *testing.T) {
	testCases := map[string]struct {
		should    bool
		errshould string
		kube      kclient.Client
		remoteRef testingfake.PushSecretData
	}{
		"Valid Secret": {
			should:    true,
			remoteRef: testingfake.PushSecretData{},
		},
		"Non-existent Secret": {
			should:    false,
			remoteRef: testingfake.PushSecretData{},
		},
		"Error case": {
			errshould: "SecretExists error",
			remoteRef: testingfake.PushSecretData{},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cl := &ovhClient{
				kube: testCase.kube,
				okmsClient: &fake.FakeOkmsClient{
					TestCase: name,
				},
			}
			ctx := context.Background()
			exists, err := cl.SecretExists(ctx, testCase.remoteRef)
			if testCase.errshould != "" && err != nil && err.Error() != testCase.errshould {
				t.Error()
			} else if (testCase.should && !exists) || (!testCase.should && exists) {
				t.Error()
			}
		})
	}
}
