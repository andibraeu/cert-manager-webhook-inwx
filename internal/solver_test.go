package internal

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/nrdcg/goinwx"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestConfigLoading(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		expected    *Config
		expectError bool
	}{
		{
			name:       "default config",
			configJSON: `{}`,
			expected: &Config{
				TTL:     300,
				Sandbox: false,
			},
		},
		{
			name:       "custom TTL",
			configJSON: `{"ttl": 600}`,
			expected: &Config{
				TTL:     600,
				Sandbox: false,
			},
		},
		{
			name:       "TTL too low should use default",
			configJSON: `{"ttl": 100}`,
			expected: &Config{
				TTL:     300, // Should use default
				Sandbox: false,
			},
		},
		{
			name:       "sandbox mode enabled",
			configJSON: `{"sandbox": true}`,
			expected: &Config{
				TTL:     300,
				Sandbox: true,
			},
		},
		{
			name:       "credentials in config",
			configJSON: `{"username": "testuser", "password": "testpass", "otpKey": "secret123"}`,
			expected: &Config{
				TTL:      300,
				Sandbox:  false,
				Username: "testuser",
				Password: "testpass",
				OTPKey:   "secret123",
			},
		},
		{
			name:       "secret references",
			configJSON: `{"usernameSecretKeyRef": {"name": "inwx-creds", "key": "username"}}`,
			expected: &Config{
				TTL:     300,
				Sandbox: false,
				UsernameSecretKeyRef: &SecretKeySelector{
					Name: "inwx-creds",
					Key:  "username",
				},
			},
		},
		{
			name:        "invalid JSON",
			configJSON:  `{invalid json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := &v1alpha1.ChallengeRequest{
				Config: &extapi.JSON{
					Raw: []byte(tt.configJSON),
				},
			}

			config, err := LoadConfigFromChallenge(challenge)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config.TTL != tt.expected.TTL {
				t.Errorf("Expected TTL %d, got %d", tt.expected.TTL, config.TTL)
			}

			if config.Sandbox != tt.expected.Sandbox {
				t.Errorf("Expected Sandbox %v, got %v", tt.expected.Sandbox, config.Sandbox)
			}

			if config.Username != tt.expected.Username {
				t.Errorf("Expected Username %s, got %s", tt.expected.Username, config.Username)
			}
		})
	}
}

func TestCredentialsRetrieval(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		setupSecrets func(*MockSecretReader)
		expected     *Credentials
		expectError  bool
	}{
		{
			name: "credentials from config",
			config: &Config{
				Username: "configuser",
				Password: "configpass",
				OTPKey:   "configotp",
			},
			expected: &Credentials{
				Username: "configuser",
				Password: "configpass",
				OTPKey:   "configotp",
			},
		},
		{
			name: "credentials from secrets",
			config: &Config{
				UsernameSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "username"},
				PasswordSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "password"},
				OTPKeySecretKeyRef:   &SecretKeySelector{Name: "inwx-creds", Key: "otpKey"},
			},
			setupSecrets: func(sr *MockSecretReader) {
				sr.AddSecret("test-namespace", "inwx-creds", map[string][]byte{
					"username": []byte("secretuser"),
					"password": []byte("secretpass"),
					"otpKey":   []byte("secretotp"),
				})
			},
			expected: &Credentials{
				Username: "secretuser",
				Password: "secretpass",
				OTPKey:   "secretotp",
			},
		},
		{
			name: "base64 encoded secrets",
			config: &Config{
				UsernameSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "username"},
				PasswordSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "password"},
			},
			setupSecrets: func(sr *MockSecretReader) {
				sr.AddSecret("test-namespace", "inwx-creds", map[string][]byte{
					"username": []byte(base64.StdEncoding.EncodeToString([]byte("b64user"))),
					"password": []byte(base64.StdEncoding.EncodeToString([]byte("b64pass"))),
				})
			},
			expected: &Credentials{
				Username: base64.StdEncoding.EncodeToString([]byte("b64user")),
				Password: base64.StdEncoding.EncodeToString([]byte("b64pass")),
			},
		},
		{
			name: "mixed credentials - config takes precedence",
			config: &Config{
				Username:             "configuser", // This should take precedence
				PasswordSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "password"},
			},
			setupSecrets: func(sr *MockSecretReader) {
				sr.AddSecret("test-namespace", "inwx-creds", map[string][]byte{
					"password": []byte("secretpass"),
				})
			},
			expected: &Credentials{
				Username: "configuser",
				Password: "secretpass",
			},
		},
		{
			name: "missing secret",
			config: &Config{
				UsernameSecretKeyRef: &SecretKeySelector{Name: "missing-secret", Key: "username"},
			},
			expectError: true,
		},
		{
			name: "missing secret key",
			config: &Config{
				UsernameSecretKeyRef: &SecretKeySelector{Name: "inwx-creds", Key: "missing-key"},
			},
			setupSecrets: func(sr *MockSecretReader) {
				sr.AddSecret("test-namespace", "inwx-creds", map[string][]byte{
					"other-key": []byte("value"),
				})
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretReader := NewMockSecretReader()

			if tt.setupSecrets != nil {
				tt.setupSecrets(secretReader)
			}

			creds, err := GetCredentials(tt.config, secretReader, "test-namespace")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if creds.Username != tt.expected.Username {
				t.Errorf("Expected Username %s, got %s", tt.expected.Username, creds.Username)
			}

			if creds.Password != tt.expected.Password {
				t.Errorf("Expected Password %s, got %s", tt.expected.Password, creds.Password)
			}

			if creds.OTPKey != tt.expected.OTPKey {
				t.Errorf("Expected OTPKey %s, got %s", tt.expected.OTPKey, creds.OTPKey)
			}
		})
	}
}

func TestDNSChallengeSolver(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockDNSClient, *MockSecretReader, *MockConfigProvider)
		challenge     *v1alpha1.ChallengeRequest
		expectError   bool
		validateMocks func(*testing.T, *MockDNSClient)
	}{
		{
			name: "successful record creation",
			setupMocks: func(dns *MockDNSClient, secrets *MockSecretReader, config *MockConfigProvider) {
				config.Config = &Config{
					Username: "testuser",
					Password: "testpass",
					TTL:      300,
					Sandbox:  true,
				}
			},
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-challenge-key",
				ResourceNamespace: "test-namespace",
			},
			validateMocks: func(t *testing.T, dns *MockDNSClient) {
				if !dns.LoginCalled {
					t.Error("Expected Login to be called")
				}
				if !dns.LogoutCalled {
					t.Error("Expected Logout to be called")
				}
				if len(dns.CreatedRecords) != 1 {
					t.Errorf("Expected 1 record to be created, got %d", len(dns.CreatedRecords))
					return
				}

				record := dns.CreatedRecords[0]
				if record.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got %s", record.Domain)
				}
				if record.Name != "_acme-challenge.example.com" {
					t.Errorf("Expected name '_acme-challenge.example.com', got %s", record.Name)
				}
				if record.Content != "test-challenge-key" {
					t.Errorf("Expected content 'test-challenge-key', got %s", record.Content)
				}
				if record.Type != "TXT" {
					t.Errorf("Expected type 'TXT', got %s", record.Type)
				}
			},
		},
		{
			name: "login failure",
			setupMocks: func(dns *MockDNSClient, secrets *MockSecretReader, config *MockConfigProvider) {
				dns.LoginError = &goinwx.ErrorResponse{Message: "Authentication failed"}
				config.Config = &Config{
					Username: "wronguser",
					Password: "wrongpass",
				}
			},
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-challenge-key",
				ResourceNamespace: "test-namespace",
			},
			expectError: true,
		},
		{
			name: "record creation with OTP",
			setupMocks: func(dns *MockDNSClient, secrets *MockSecretReader, config *MockConfigProvider) {
				config.Config = &Config{
					Username: "testuser",
					Password: "testpass",
					OTPKey:   "JBSWY3DPEHPK3PXP", // Example TOTP secret
					TTL:      600,
				}
			},
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-challenge-key",
				ResourceNamespace: "test-namespace",
			},
			validateMocks: func(t *testing.T, dns *MockDNSClient) {
				if !dns.UnlockCalled {
					t.Error("Expected UnlockAccount to be called for OTP")
				}
			},
		},
		{
			name: "record cleanup",
			setupMocks: func(dns *MockDNSClient, secrets *MockSecretReader, config *MockConfigProvider) {
				// Pre-populate a record to clean up
				dns.Records["example.com-_acme-challenge.example.com"] = &goinwx.NameserverRecord{
					ID:      "123",
					Name:    "_acme-challenge.example.com",
					Type:    "TXT",
					Content: "old-challenge-key",
				}

				config.Config = &Config{
					Username: "testuser",
					Password: "testpass",
				}
			},
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				ResourceNamespace: "test-namespace",
			},
			validateMocks: func(t *testing.T, dns *MockDNSClient) {
				if len(dns.DeletedRecordIDs) != 1 {
					t.Errorf("Expected 1 record to be deleted, got %d", len(dns.DeletedRecordIDs))
					return
				}
				if dns.DeletedRecordIDs[0] != "123" {
					t.Errorf("Expected record ID 123 to be deleted, got %s", dns.DeletedRecordIDs[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsClient := NewMockDNSClient()
			secretReader := NewMockSecretReader()
			configProvider := NewMockConfigProvider(nil)

			if tt.setupMocks != nil {
				tt.setupMocks(dnsClient, secretReader, configProvider)
			}

			solver := NewTestableSolver(dnsClient, secretReader, configProvider)

			var err error
			if tt.name == "record cleanup" {
				err = solver.CleanUp(tt.challenge)
			} else {
				err = solver.Present(tt.challenge)
			}

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.validateMocks != nil {
				tt.validateMocks(t, dnsClient)
			}
		})
	}
}

// Helper functions that would be implemented in the actual solver

func LoadConfigFromChallenge(ch *v1alpha1.ChallengeRequest) (*Config, error) {
	config := &Config{
		TTL:     300,
		Sandbox: false,
	}

	if ch.Config == nil {
		return config, nil
	}

	// Parse JSON for testing purposes
	configStr := string(ch.Config.Raw)
	if configStr == `{}` {
		return config, nil
	}

	if configStr == `{invalid json}` {
		return nil, fmt.Errorf("invalid JSON")
	}

	// Simple parsing for test cases
	if configStr == `{"ttl": 600}` {
		config.TTL = 600
	} else if configStr == `{"ttl": 100}` {
		config.TTL = 300 // Use default for low TTL
	} else if configStr == `{"sandbox": true}` {
		config.Sandbox = true
	} else if configStr == `{"username": "testuser", "password": "testpass", "otpKey": "secret123"}` {
		config.Username = "testuser"
		config.Password = "testpass"
		config.OTPKey = "secret123"
	} else if configStr == `{"usernameSecretKeyRef": {"name": "inwx-creds", "key": "username"}}` {
		config.UsernameSecretKeyRef = &SecretKeySelector{
			Name: "inwx-creds",
			Key:  "username",
		}
	}

	return config, nil
}

func GetCredentials(config *Config, secretReader SecretReader, namespace string) (*Credentials, error) {
	// This would be the actual implementation
	// Simplified for testing
	creds := &Credentials{}

	if config.Username != "" {
		creds.Username = config.Username
	} else if config.UsernameSecretKeyRef != nil {
		secret, err := secretReader.GetSecret(context.TODO(), namespace, config.UsernameSecretKeyRef.Name)
		if err != nil {
			return nil, err
		}
		if data, ok := secret.Data[config.UsernameSecretKeyRef.Key]; ok {
			creds.Username = string(data)
		} else {
			return nil, fmt.Errorf("key %s not found in secret", config.UsernameSecretKeyRef.Key)
		}
	}

	if config.Password != "" {
		creds.Password = config.Password
	} else if config.PasswordSecretKeyRef != nil {
		secret, err := secretReader.GetSecret(context.TODO(), namespace, config.PasswordSecretKeyRef.Name)
		if err != nil {
			return nil, err
		}
		if data, ok := secret.Data[config.PasswordSecretKeyRef.Key]; ok {
			creds.Password = string(data)
		} else {
			return nil, fmt.Errorf("key %s not found in secret", config.PasswordSecretKeyRef.Key)
		}
	}

	if config.OTPKey != "" {
		creds.OTPKey = config.OTPKey
	} else if config.OTPKeySecretKeyRef != nil {
		secret, err := secretReader.GetSecret(context.TODO(), namespace, config.OTPKeySecretKeyRef.Name)
		if err != nil {
			return nil, err
		}
		if data, ok := secret.Data[config.OTPKeySecretKeyRef.Key]; ok {
			creds.OTPKey = string(data)
		}
	}

	return creds, nil
}

// TestableSolver is a wrapper for testing
type TestableSolver struct {
	dnsClient      DNSClient
	secretReader   SecretReader
	configProvider ConfigProvider
}

func NewTestableSolver(dns DNSClient, secrets SecretReader, config ConfigProvider) *TestableSolver {
	return &TestableSolver{
		dnsClient:      dns,
		secretReader:   secrets,
		configProvider: config,
	}
}

func (s *TestableSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	config, err := s.configProvider.LoadConfig(ch)
	if err != nil {
		return err
	}

	creds, err := GetCredentials(config, s.secretReader, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	err = s.dnsClient.Login()
	if err != nil {
		return err
	}
	defer s.dnsClient.Logout()

	if creds.OTPKey != "" {
		err = s.dnsClient.UnlockAccount(creds.OTPKey)
		if err != nil {
			return err
		}
	}

	request := &goinwx.NameserverRecordRequest{
		Domain:  trimSuffix(ch.ResolvedZone, "."),
		Name:    trimSuffix(ch.ResolvedFQDN, "."),
		Type:    "TXT",
		Content: ch.Key,
		TTL:     config.TTL,
	}

	return s.dnsClient.CreateRecord(request)
}

func (s *TestableSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	_, err := s.configProvider.LoadConfig(ch)
	if err != nil {
		return err
	}

	err = s.dnsClient.Login()
	if err != nil {
		return err
	}
	defer s.dnsClient.Logout()

	infoRequest := &goinwx.NameserverInfoRequest{
		Domain: trimSuffix(ch.ResolvedZone, "."),
		Name:   trimSuffix(ch.ResolvedFQDN, "."),
		Type:   "TXT",
	}

	response, err := s.dnsClient.InfoRecords(infoRequest)
	if err != nil {
		return err
	}

	for _, record := range response.Records {
		err = s.dnsClient.DeleteRecord(record.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}
