package ovh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/esutils/resolvers"
	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type Provider struct {
	SecretKeyRef func(ctx context.Context, c kclient.Client, storeKind string, esNamespace string, ref *esmeta.SecretKeySelector) (string, error)
}

type OkmsClient interface {
	GetSecretV2(ctx context.Context, okmsId uuid.UUID, path string, version *uint32, includeData *bool) (*types.GetSecretV2Response, error)
	ListSecretV2(ctx context.Context, okmsId uuid.UUID, pageSize *uint32, pageCursor *string) (*types.ListSecretV2ResponseWithPagination, error)
	PostSecretV2(ctx context.Context, okmsId uuid.UUID, body types.PostSecretV2Request) (*types.PostSecretV2Response, error)
	PutSecretV2(ctx context.Context, okmsId uuid.UUID, path string, cas *uint32, body types.PutSecretV2Request) (*types.PutSecretV2Response, error)
	DeleteSecretV2(ctx context.Context, okmsId uuid.UUID, path string) error
	WithCustomHeader(key, value string) *okms.Client
	GetSecretsMetadata(ctx context.Context, okmsId uuid.UUID, path string, list bool) (*types.GetMetadataResponse, error)
}

type ovhClient struct {
	ovhStoreNameSpace string
	ovhStoreKind      string
	kube              kclient.Client
	okmsId            uuid.UUID
	cas               bool
	okmsClient        OkmsClient
}

var _ esv1.SecretsClient = &ovhClient{}

// Create a new Provider client.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	// Validate Store before creating a client from it.
	_, err := p.ValidateStore(store)
	if err != nil {
		return nil, err
	}

	if kube == nil {
		return nil, errors.New("controller-runtime client is nil")
	}

	ovhStore := store.GetSpec().Provider.Ovh
	// ovhClient configuration.
	okmsId, err := uuid.Parse(ovhStore.OkmsID)
	if err != nil {
		return nil, err
	}

	cas := false
	if ovhStore.CasRequired != nil {
		cas = *ovhStore.CasRequired
	}

	cl := &ovhClient{
		ovhStoreNameSpace: namespace,
		ovhStoreKind:      store.GetKind(),
		kube:              kube,
		okmsId:            okmsId,
		cas:               cas,
	}

	// Authentication configuration: token or mTLS.
	if p.SecretKeyRef == nil {
		p.SecretKeyRef = resolvers.SecretKeyRef
	}
	if ovhStore.Auth.ClientToken != nil {
		err = configureHttpTokenClient(ctx, p, cl,
			ovhStore.Server, ovhStore.Auth.ClientToken)
	} else if ovhStore.Auth.ClientMTLS != nil {
		err = configureHttpMTLSClient(ctx, p, cl,
			ovhStore.Server, ovhStore.Auth.ClientMTLS)
	}
	return cl, err
}

// Configure the client to use the provided token for HTTP requests.
func configureHttpTokenClient(ctx context.Context, p *Provider, cl *ovhClient, server string, clientToken *esv1.OvhClientToken) error {
	token, err := getToken(ctx, p, cl, clientToken)
	if err != nil {
		return err
	}
	bearer_token := fmt.Sprintf("Bearer %s", token)

	// Request a new OKMS client from the OVH SDK.
	cl.okmsClient, err = okms.NewRestAPIClientWithHttp(server, &http.Client{})
	if err != nil {
		return err
	}
	if cl.okmsClient == nil {
		return errors.New("failed to get new okms client")
	}

	// Add a custom header.
	if cl.okmsClient.WithCustomHeader("Authorization", bearer_token) == nil {
		return errors.New("failed to add custom header to okms client")
	}
	if cl.okmsClient.WithCustomHeader("Content-type", "application/json") == nil {
		return errors.New("failed to add custom header to okms client")
	}

	return nil
}

// Configure the client to use mTLS for HTTP requests.
func configureHttpMTLSClient(ctx context.Context, p *Provider, cl *ovhClient, server string, clientMTLS *esv1.OvhClientMTLS) error {
	tlsCert, err := getMTLS(ctx, p, cl, clientMTLS)
	if err != nil {
		return err
	}

	// HTTP client configuration using mTLS.
	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}

	// Request a new OKMS client from the OVH SDK (mTLS configured).
	cl.okmsClient, err = okms.NewRestAPIClientWithHttp(server, &httpClient)
	if err != nil {
		return err
	}
	if cl.okmsClient == nil {
		return errors.New("failed to get new okms client")
	}

	return err
}

// Retrieve the token value from the Kubernetes secret.
func getToken(ctx context.Context, p *Provider, cl *ovhClient, clientToken *esv1.OvhClientToken) (string, error) {
	// ClienTokenSecret refers to the Kubernetes secret that stores the token.
	tokenSecretRef := clientToken.ClientTokenSecret
	if tokenSecretRef == nil {
		return "", errors.New("ovh store auth.token.tokenSecretRef cannot be empty")
	}

	// Retrieve the token value.
	token, err := p.SecretKeyRef(ctx, cl.kube,
		cl.ovhStoreKind, cl.ovhStoreNameSpace, tokenSecretRef)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("ovh store auth.token.tokenSecretRef cannot be empty")
	}

	return token, nil
}

// Retrieve the client key and certificate from the Kubernetes secret.
func getMTLS(ctx context.Context, p *Provider, cl *ovhClient, clientMTLS *esv1.OvhClientMTLS) (tls.Certificate, error) {
	const (
		emptyKeySecretRef  = "ovh store auth.mtls.keySecretRef cannot be empty"
		emptyCertSecretRef = "ovh store auth.mtls.certSecretRef cannot be empty"
	)
	// keySecretRef refers to the Kubernetes secret object
	// containing the client key.
	keyRef := clientMTLS.ClientKey
	if keyRef == nil {
		return tls.Certificate{}, errors.New(emptyKeySecretRef)
	}
	// Retrieve the value of keySecretRef from the Kubernetes secret.
	clientKey, err := p.SecretKeyRef(ctx, cl.kube,
		cl.ovhStoreKind, cl.ovhStoreNameSpace, keyRef)
	if err != nil {
		return tls.Certificate{}, err
	}
	if clientKey == "" {
		return tls.Certificate{}, errors.New(emptyKeySecretRef)
	}

	// certSecretRef refers to the Kubernetes secret object
	// containing the client certificate.
	certRef := clientMTLS.ClientCertificate
	if certRef == nil {
		return tls.Certificate{}, errors.New(emptyCertSecretRef)
	}
	// Retrieve the value of certSecretRef from the Kubernetes secret.
	clientCert, err := p.SecretKeyRef(ctx, cl.kube,
		cl.ovhStoreKind, cl.ovhStoreNameSpace, certRef)
	if err != nil {
		return tls.Certificate{}, err
	}
	if clientCert == "" {
		return tls.Certificate{}, errors.New(emptyCertSecretRef)
	}

	cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))

	return cert, err
}

// Statically validate the Secret Store specification.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	// Nil checks.
	if store == nil || reflect.ValueOf(store).IsNil() {
		return nil, errors.New("store is nil")
	}
	spec := store.GetSpec()
	if spec == nil {
		return nil, errors.New("store spec is nil")
	}
	provider := spec.Provider
	if provider == nil {
		return nil, errors.New("store provider is nil")
	}
	if provider.Ovh == nil {
		return nil, errors.New("ovh store provider is nil")
	}

	// Validate the provider's authentication method.
	auth := provider.Ovh.Auth
	if auth.ClientMTLS == nil && auth.ClientToken == nil {
		return nil, errors.New("missing authentication method")
	} else if auth.ClientMTLS != nil && auth.ClientToken != nil {
		return nil, errors.New("only one authentication method allowed (mtls | token)")
	} else if auth.ClientMTLS != nil &&
		(auth.ClientMTLS.ClientCertificate == nil ||
			auth.ClientMTLS.ClientKey == nil) {
		return nil, errors.New("missing tls certificate or key")
	}

	return nil, nil
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// init registers the OVH provider with the External Secrets Operator.
func init() {
	esv1.Register(&Provider{}, &esv1.SecretStoreProvider{
		Ovh: &esv1.OvhProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
