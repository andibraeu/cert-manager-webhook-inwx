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

	klog.V(2).Infof("present request: fqdn=%q zone=%q namespace=%q key_len=%d", ch.ResolvedFQDN, ch.ResolvedZone, ch.ResourceNamespace, len(ch.Key))

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

	klog.V(2).Infof("creating DNS record: domain=%q name=%q type=%q ttl=%d content_len=%d sandbox=%t", request.Domain, request.Name, request.Type, request.TTL, len(request.Content), cfg.Sandbox)

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

	klog.V(2).Infof("cleanup request: fqdn=%q zone=%q namespace=%q", ch.ResolvedFQDN, ch.ResolvedZone, ch.ResourceNamespace)

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

	infoRequest := &goinwx.NameserverInfoRequest{
		Domain: strings.TrimRight(ch.ResolvedZone, "."),
		Name:   strings.TrimRight(ch.ResolvedFQDN, "."),
		Type:   "TXT",
	}

	klog.V(2).Infof("listing DNS records: domain=%q name=%q type=%q", infoRequest.Domain, infoRequest.Name, infoRequest.Type)

	response, err := client.Nameservers.Info(infoRequest)
	if err != nil {
		klog.Error(err)
		return fmt.Errorf("%v", err)
	}

	var lastErr error
	klog.V(2).Infof("found %d DNS records to delete", len(response.Records))
	for _, record := range response.Records {
		klog.V(3).Infof("deleting DNS record id=%q name=%q type=%q", record.ID, record.Name, record.Type)
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
		klog.V(3).Info("using username from config")
		creds.Username = config.Username
	} else {
		klog.V(3).Infof("loading username from secret %q key %q", ns+"/"+config.UsernameSecretKeyRef.Name, config.UsernameSecretKeyRef.Key)
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
		klog.V(3).Info("using password from config")
		creds.Password = config.Password
	} else {
		klog.V(3).Infof("loading password from secret %q key %q", ns+"/"+config.PasswordSecretKeyRef.Name, config.PasswordSecretKeyRef.Key)
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
		klog.V(3).Info("using OTP key from config")
		creds.OTPKey = config.OTPKey
	} else if config.OTPKeySecretKeyRef.Key != "" {
		klog.V(3).Infof("loading OTP key from secret %q key %q", ns+"/"+config.OTPKeySecretKeyRef.Name, config.OTPKeySecretKeyRef.Key)
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

	klog.V(3).Infof(
		"config summary: ttl=%d sandbox=%t username_inline=%t password_inline=%t otp_inline=%t username_ref=%t password_ref=%t otp_ref=%t",
		cfg.TTL,
		cfg.Sandbox,
		cfg.Username != "",
		cfg.Password != "",
		cfg.OTPKey != "",
		cfg.UsernameSecretKeyRef.Name != "",
		cfg.PasswordSecretKeyRef.Name != "",
		cfg.OTPKeySecretKeyRef.Name != "",
	)

	klog.V(5).Infof("decoded config: %v", cfg)

	creds, err := s.getCredentials(&cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, &cfg, fmt.Errorf("error getting credentials: %v", err)
	}

	client := goinwx.NewClient(creds.Username, creds.Password, &goinwx.ClientOptions{Sandbox: cfg.Sandbox})

	klog.V(2).Infof("logging in to INWX API (sandbox=%t)", cfg.Sandbox)
	_, err = client.Account.Login()
	if err != nil {
		klog.Error(err)
		return nil, &cfg, fmt.Errorf("%v", err)
	}

	if creds.OTPKey != "" {
		klog.V(2).Info("unlocking INWX account with OTP")
		err, formattedError := tryToUnlockWithOTPKey(creds, client, true)
		if err != nil {
			return nil, &cfg, formattedError
		}
	}

	klog.V(3).Infof("logged in at INWX API")

	return client, &cfg, nil
}

func tryToUnlockWithOTPKey(creds *credentials, client *goinwx.Client, retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy bool) (error, error) {
	klog.V(3).Infof("generating TOTP code (retry=%t)", retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy)
	tan, err := totp.GenerateCode(creds.OTPKey, time.Now())
	if err != nil {
		klog.Error(err)
		return nil, fmt.Errorf("error generating opt-key: %v", err)
	}

	klog.V(3).Info("unlocking INWX account with generated TOTP")
	err = client.Account.Unlock(tan)

	if err != nil && retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy {
		klog.V(2).Info("OTP unlock failed; retrying after pause to satisfy INWX single-use policy")
		time.Sleep(30 * time.Second)
		return tryToUnlockWithOTPKey(creds, client, false)
	} else if err != nil {
		klog.Error(err)
		return err, fmt.Errorf("error Unlock opt-key: %v", err)
	}

	return nil, nil
}
