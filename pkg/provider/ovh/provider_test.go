package ovh

import (
	"context"
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var namespace string = "namespace"
var scheme = runtime.NewScheme()
var _ = corev1.AddToScheme(scheme)
var kube = fake.NewClientBuilder().
	WithScheme(scheme).
	WithObjects(&corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}).Build()

func TestNewClient(t *testing.T) {
	tests := map[string]struct {
		should string
		kube   kclient.Client
		err    bool
		store  *esv1.SecretStore
	}{
		"Nil store": {
			should: "store is nil",
			err:    true,
			kube:   kube,
		},
		"Nil provider": {
			should: "store provider is nil",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: nil,
				},
			},
		},
		"Nil ovh provider": {
			should: "ovh store provider is nil",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						AWS: &esv1.AWSProvider{},
					},
				},
			},
		},
		"Nil controller-runtime client": {
			should: "controller-runtime client is nil",
			err:    true,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Auth: esv1.OvhAuth{
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{
										Name:      "Valid token auth",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Authentication method conflict": {
			should: "only one authentication method allowed (mtls | token)",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Authentication method empty": {
			should: "missing authentication method",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth:   esv1.OvhAuth{},
						},
					},
				},
			},
		},
		"Valid token auth": {
			should: "",
			err:    false,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{
										Name:      "Valid token auth",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Empty token auth": {
			should: "ovh store auth.token.tokenSecretRef cannot be empty",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{},
								},
							},
						},
					},
				},
			},
		},
		"Valid mtls auth": {
			should: "",
			err:    false,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "Valid mtls client certificate",
										Namespace: &namespace,
										Key:       "string",
									},
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "Valid mtls client key",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Empty mtls client certificate": {
			should: "missing tls certificate or key",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "Valid mtls client key",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Empty mtls client key": {
			should: "missing tls certificate or key",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "Valid mtls client certificate",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	ctx := context.Background()
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			provider := Provider{
				SecretKeyRef: SecretKeyRef,
			}
			_, err := provider.NewClient(ctx, testCase.store, testCase.kube, "namespace")
			if testCase.err == true {
				if err == nil {
					t.Error()
				} else if err.Error() != testCase.should {
					t.Error()
				}
			} else if err != nil {
				t.Error()
			}
		})
	}
}

func SecretKeyRef(ctx context.Context, c kclient.Client, storeKind, esNamespace string, ref *esmeta.SecretKeySelector) (string, error) {
	switch ref.Name {
	case "Valid token auth":
		return "Valid", nil
	case "Valid mtls client certificate":
		const clientCertPEM = `-----BEGIN CERTIFICATE-----
MIICDDCCAXUCFBLEQBCxspRPCp8BfOtrifCv1B3SMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjUxMjE3MTQ1NTQwWhcNMjYxMjE3MTQ1
NTQwWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC2YZzXoQ4pHjVAHSJzs1g+J6LBkeBA5bRPEL3BZoPtxX0GhXgfc37c
FDpWH9DRfkcndwO29yh5Rrjdf24UES25HkTPrrGc6CICEsxHWvm00kgMU32SqVhD
dO3pwkEcbLzxNcu0xcfQO767lwT8j5BpESGTLmey1t1aHrHgTZ8DowIDAQABMA0G
CSqGSIb3DQEBCwUAA4GBAAV0XtV9GG8tk2Fz1Fy4hztyU17ZZccx3bYgPUrLo6b5
YFO8LRrvmLICMJwgeiy2VBDb5WAP34C4yN0jv5OQaI45bHMffud8ADkBSBM9RAvb
HMzKCq4wjntZHFhsu9u2OPOoU/Rey7EQhnsnO0w2oAbnjaqamAKL4uRuZQQHPtjo
-----END CERTIFICATE-----`
		return clientCertPEM, nil
	case "Valid mtls client key":
		const clientKeyPEM = `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALZhnNehDikeNUAd
InOzWD4nosGR4EDltE8QvcFmg+3FfQaFeB9zftwUOlYf0NF+Ryd3A7b3KHlGuN1/
bhQRLbkeRM+usZzoIgISzEda+bTSSAxTfZKpWEN07enCQRxsvPE1y7TFx9A7vruX
BPyPkGkRIZMuZ7LW3VoeseBNnwOjAgMBAAECgYEAiw64GIzbECzRKzZLm24mHRX5
eZ+xHapGpXY9SGXSt4s5faxsX4afNkxSAnK1s9WViRisg2fFu1pZ/8B2fORwOAe8
VHAvRqsBTLZUKGR3Pm7S0zNGPcYw6X4HJi7cPDpdOUUBUy8Zg+dRcqMlHx4vaBmE
o0HqADbRjNiVmAebMoECQQDp2v2BwwVr68ugwqdb0HxihK862esPAWE69tg3D/iF
WLo7BdMVxMb/CBPVfE6tw+z8T0MzeRSYY7V2X5lccFfjAkEAx6bPv+brAHTcPlxc
T63AntlTm4yun+JfwTqjE+bajrJcRm8ij2Y15EFDWASoo7K0EqqAWbRUw2ReTNw1
2vTxQQJAFuP/sobzbefry7WiCiOzOTWBrYINNy/MY6gr69/dVLglqodcbSIQ1H/m
6Ru829d0yBG+Iziz4mLILWkYKus4PwJBAJ4kNHS17TkcV4QR1pDKeUOZs08HnR5J
yj0dPCU8e6wB/XNQ/lgFxvQ4+aXTctzPZTFP2oCzhVyLuOI6n3IDCMECQQCErbRe
lJZuvpUXsinpM3EfgB1NXmqTx3U4BTOJbNQqeXou7J/XbwO3TV37ARsP/iTqoh5S
oT11tLXIyFX0l2Ul
-----END PRIVATE KEY-----`
		return clientKeyPEM, nil
	}
	return "", nil
}

func TestValidateStore(t *testing.T) {
	var namespace string = "namespace"
	tests := map[string]struct {
		should string
		err    bool
		kube   kclient.Client
		store  *esv1.SecretStore
	}{
		"Nil store": {
			should: "store provider is nil",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: nil,
				},
			},
		},
		"Nil ovh provider": {
			should: "ovh store provider is nil",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						AWS: &esv1.AWSProvider{},
					},
				},
			},
		},
		"Authentication method conflict": {
			should: "only one authentication method allowed (mtls | token)",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Valid token auth": {
			should: "",
			err:    false,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientToken: &esv1.OvhClientToken{
									ClientTokenSecret: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Valid mtls auth": {
			should: "",
			err:    false,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Invalid mtls auth: missing client certificate": {
			should: "missing tls certificate or key",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientKey: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Invalid mtls auth: missing key certificate": {
			should: "missing tls certificate or key",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
							Auth: esv1.OvhAuth{
								ClientMTLS: &esv1.OvhClientMTLS{
									ClientCertificate: &esmeta.SecretKeySelector{
										Name:      "string",
										Namespace: &namespace,
										Key:       "string",
									},
								},
							},
						},
					},
				},
			},
		},
		"Empty auth": {
			should: "missing authentication method",
			err:    true,
			kube:   kube,
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Ovh: &esv1.OvhProvider{
							Server: "string",
							OkmsID: "11111111-1111-1111-1111-111111111111",
						},
					},
				},
			},
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			provider := Provider{}
			_, err := provider.ValidateStore(testCase.store)
			if testCase.err == true {
				if err == nil {
					t.Error()
				} else if err.Error() != testCase.should {
					t.Error()
				}
			} else if err != nil {
				t.Error()
			}
		})
	}
}
