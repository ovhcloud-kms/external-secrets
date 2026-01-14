package v1

import esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"

type OvhProvider struct {
	Server      string  `json:"server"`
	OkmsID      string  `json:"okmsid"`
	CasRequired *bool   `json:"casRequired,omitempty"`
	Auth        OvhAuth `json:"auth"`
}

type OvhAuth struct {
	ClientMTLS  *OvhClientMTLS  `json:"mtls,omitempty"`
	ClientToken *OvhClientToken `json:"token,omitempty"`
}

type OvhClientMTLS struct {
	ClientCertificate *esmeta.SecretKeySelector `json:"certSecretRef,omitempty"`
	ClientKey         *esmeta.SecretKeySelector `json:"keySecretRef,omitempty"`
}

type OvhClientToken struct {
	ClientTokenSecret *esmeta.SecretKeySelector `json:"tokenSecretRef,omitempty"`
}
