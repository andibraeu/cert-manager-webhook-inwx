package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/nrdcg/goinwx"
	"github.com/pquerna/otp/totp"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"strings"
	"time"
)

func main() {
	cmd.RunWebhookServer("cert-manager-webhook-inwx.smueller18.gitlab.com",
		&solver{},
	)
}

type credentials struct {
	Username string
	Password string
	OTPKey   string
}

type solver struct {
	client *kubernetes.Clientset
	ttl    int
}

type config struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	TTL                  int                         `json:"ttl,omitempty"`
	Sandbox              bool                        `json:"sandbox,omitempty"`
	Username             string                      `json:"username"`
	Password             string                      `json:"password"`
	OTPKey               string                      `json:"otpKey"`
	UsernameSecretKeyRef certmgrv1.SecretKeySelector `json:"usernameSecretKeyRef"`
	PasswordSecretKeyRef certmgrv1.SecretKeySelector `json:"passwordSecretKeyRef"`
	OTPKeySecretKeyRef   certmgrv1.SecretKeySelector `json:"otpKeySecretKeyRef"`
}

var defaultConfig = config{
	TTL:     300,
	Sandbox: false,
}

func (s *solver) Name() string {
	return "inwx"
}

func (s *solver) Present(ch *v1alpha1.ChallengeRequest) error {

	client, cfg, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}

	defer func() {
		if err := client.Account.Logout(); err != nil {
			klog.Errorf("failed to log out from INWX API: %v", err)
		}
		klog.V(3).Infof("logged out from INWX API")
	}()

	var request = &goinwx.NameserverRecordRequest{
		Domain:  strings.TrimRight(ch.ResolvedZone, "."),
		Name:    strings.TrimRight(ch.ResolvedFQDN, "."),
		Type:    "TXT",
		Content: ch.Key,
		TTL:     cfg.TTL,
	}

	_, err = client.Nameservers.CreateRecord(request)
	if err != nil {
		switch er := err.(type) {
		case *goinwx.ErrorResponse:
			if er.Message == "Object exists" {
				klog.Warningf("key already exists for host %v", ch.ResolvedFQDN)
				return nil
			}
			klog.Error(err)
			return fmt.Errorf("%v", err)
		default:
			klog.Error(err)
			return fmt.Errorf("%v", err)
		}
	} else {
		klog.V(2).Infof("created DNS record %v", request)
	}

	return nil
}

func (s *solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {

	client, _, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}

	defer func() {
		if err := client.Account.Logout(); err != nil {
			klog.Errorf("failed to log out from INWX API: %v", err)
		}
		klog.V(3).Infof("logged out from INWX API")
	}()

	response, err := client.Nameservers.Info(&goinwx.NameserverInfoRequest{
		Domain: strings.TrimRight(ch.ResolvedZone, "."),
		Name:   strings.TrimRight(ch.ResolvedFQDN, "."),
		Type:   "TXT",
	})
	if err != nil {
		klog.Error(err)
		return fmt.Errorf("%v", err)
	}

	var lastErr error
	for _, record := range response.Records {
		err = client.Nameservers.DeleteRecord(record.ID)
		if err != nil {
			klog.Error(err)
			lastErr = fmt.Errorf("%v", err)
		}
		klog.V(2).Infof("deleted DNS record %v", record)
	}

	return lastErr
}

func (s *solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	s.client = cl

	return nil
}

func (s *solver) getCredentials(config *config, ns string) (*credentials, error) {

	creds := credentials{}

	if config.Username != "" {
		creds.Username = config.Username
	} else {
		secret, err := s.client.CoreV1().Secrets(ns).Get(context.Background(), config.UsernameSecretKeyRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to load secret %q", ns+"/"+config.UsernameSecretKeyRef.Name)
		}
		if username, ok := secret.Data[config.UsernameSecretKeyRef.Key]; ok {
			creds.Username = string(username)
		} else {
			return nil, fmt.Errorf("no key %q in secret %q", config.UsernameSecretKeyRef, ns+"/"+config.UsernameSecretKeyRef.Name)
		}
	}

	if config.Password != "" {
		creds.Password = config.Password
	} else {
		secret, err := s.client.CoreV1().Secrets(ns).Get(context.Background(), config.PasswordSecretKeyRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to load secret %q", ns+"/"+config.PasswordSecretKeyRef.Name)
		}
		if password, ok := secret.Data[config.PasswordSecretKeyRef.Key]; ok {
			creds.Password = string(password)
		} else {
			return nil, fmt.Errorf("no key %q in secret %q", config.PasswordSecretKeyRef, ns+"/"+config.PasswordSecretKeyRef.Name)
		}
	}

	if config.OTPKey != "" {
		creds.OTPKey = config.OTPKey
	} else if config.OTPKeySecretKeyRef.Key != "" {
		secret, err := s.client.CoreV1().Secrets(ns).Get(context.Background(), config.OTPKeySecretKeyRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to load secret %q", ns+"/"+config.OTPKeySecretKeyRef.Name)
		}
		if otpKey, ok := secret.Data[config.OTPKeySecretKeyRef.Key]; ok {
			creds.OTPKey = string(otpKey)
		} else {
			return nil, fmt.Errorf("no key %q in secret %q", config.OTPKeySecretKeyRef, ns+"/"+config.OTPKeySecretKeyRef.Name)
		}
	}

	return &creds, nil
}

func loadConfig(cfgJSON *extapi.JSON) (config, error) {
	cfg := config{}
	if cfgJSON == nil {
		return defaultConfig, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = defaultConfig.TTL
	} else if cfg.TTL < 300 {
		klog.Warningf("TTL must be greater or equal than 300. Using default %q", defaultConfig.TTL)
		cfg.TTL = defaultConfig.TTL
	}

	return cfg, nil
}

func (s *solver) newClientFromChallenge(ch *v1alpha1.ChallengeRequest) (*goinwx.Client, *config, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, &cfg, err
	}
	s.ttl = cfg.TTL

	klog.V(5).Infof("decoded config: %v", cfg)

	creds, err := s.getCredentials(&cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, &cfg, fmt.Errorf("error getting credentials: %v", err)
	}

	client := goinwx.NewClient(creds.Username, creds.Password, &goinwx.ClientOptions{Sandbox: cfg.Sandbox})

	_, err = client.Account.Login()
	if err != nil {
		klog.Error(err)
		return nil, &cfg, fmt.Errorf("%v", err)
	}

	if creds.OTPKey != "" {
		err, formattedError := tryToUnlockWithOTPKey(creds, client, true)
		if err != nil {
			return nil, &cfg, formattedError
		}
	}

	klog.V(3).Infof("logged in at INWX API")

	return client, &cfg, nil
}

func tryToUnlockWithOTPKey(creds *credentials, client *goinwx.Client, retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy bool) (error, error) {
	tan, err := totp.GenerateCode(creds.OTPKey, time.Now())
	if err != nil {
		klog.Error(err)
		return nil, fmt.Errorf("error generating opt-key: %v", err)
	}

	err = client.Account.Unlock(tan)

	if err != nil && retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy {
		time.Sleep(30 * time.Second)
		return tryToUnlockWithOTPKey(creds, client, false)
	} else if err != nil {
		klog.Error(err)
		return err, fmt.Errorf("error Unlock opt-key: %v", err)
	}

	return nil, nil
}
