package internal

import (
	"context"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/nrdcg/goinwx"
	corev1 "k8s.io/api/core/v1"
)

// DNSClient interface abstracts INWX API operations
type DNSClient interface {
	Login() error
	Logout() error
	CreateRecord(request *goinwx.NameserverRecordRequest) error
	InfoRecords(request *goinwx.NameserverInfoRequest) (*NameserverInfoResponse, error)
	DeleteRecord(recordID string) error
	UnlockAccount(otpKey string) error
}

// NameserverInfoResponse mimics the response from goinwx
type NameserverInfoResponse struct {
	Records []goinwx.NameserverRecord `json:"records"`
}

// SecretReader interface abstracts Kubernetes secret operations
type SecretReader interface {
	GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
}

// ConfigProvider interface abstracts configuration loading
type ConfigProvider interface {
	LoadConfig(ch *v1alpha1.ChallengeRequest) (*Config, error)
}

// Solver interface for the DNS challenge solver
type Solver interface {
	Present(ch *v1alpha1.ChallengeRequest) error
	CleanUp(ch *v1alpha1.ChallengeRequest) error
	Initialize(secretReader SecretReader, configProvider ConfigProvider) error
}

// Config represents the webhook configuration
type Config struct {
	TTL                  int                `json:"ttl,omitempty"`
	Sandbox              bool               `json:"sandbox,omitempty"`
	Username             string             `json:"username"`
	Password             string             `json:"password"`
	OTPKey               string             `json:"otpKey"`
	UsernameSecretKeyRef *SecretKeySelector `json:"usernameSecretKeyRef"`
	PasswordSecretKeyRef *SecretKeySelector `json:"passwordSecretKeyRef"`
	OTPKeySecretKeyRef   *SecretKeySelector `json:"otpKeySecretKeyRef"`
}

// SecretKeySelector represents a reference to a secret key
type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// Credentials holds INWX authentication data
type Credentials struct {
	Username string
	Password string
	OTPKey   string
}
