package main

import (
	"fmt"
	"testing"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// TestConfigLoading tests configuration parsing and validation
func TestConfigLoading(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		expectedTTL int
		expectedSandbox bool
		expectError bool
	}{
		{
			name:        "default config",
			configJSON:  `{}`,
			expectedTTL: 300,
			expectedSandbox: false,
		},
		{
			name:        "custom TTL",
			configJSON:  `{"ttl": 600}`,
			expectedTTL: 600,
			expectedSandbox: false,
		},
		{
			name:        "TTL too low should use default",
			configJSON:  `{"ttl": 100}`,
			expectedTTL: 300, // Should use default
			expectedSandbox: false,
		},
		{
			name:        "sandbox mode enabled",
			configJSON:  `{"sandbox": true}`,
			expectedTTL: 300,
			expectedSandbox: true,
		},
		{
			name:        "invalid JSON",
			configJSON:  `{invalid json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jsonData *extapi.JSON
			if tt.configJSON != "" {
				jsonData = &extapi.JSON{Raw: []byte(tt.configJSON)}
			}

			config, err := loadConfig(jsonData)
			
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

			if config.TTL != tt.expectedTTL {
				t.Errorf("Expected TTL %d, got %d", tt.expectedTTL, config.TTL)
			}

			if config.Sandbox != tt.expectedSandbox {
				t.Errorf("Expected Sandbox %v, got %v", tt.expectedSandbox, config.Sandbox)
			}
		})
	}
}

// TestCredentialsValidation tests credential validation logic
func TestCredentialsValidation(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		password    string
		expectError bool
	}{
		{
			name:     "valid credentials",
			username: "testuser",
			password: "testpass",
		},
		{
			name:        "missing username",
			password:    "testpass",
			expectError: true,
		},
		{
			name:        "missing password",
			username:    "testuser",
			expectError: true,
		},
		{
			name:        "both missing",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := &credentials{
				Username: tt.username,
				Password: tt.password,
			}

			err := validateCredentials(creds)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDomainNameProcessing tests domain name processing logic
func TestDomainNameProcessing(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		fqdn     string
		expected string
	}{
		{
			name:     "standard domain",
			zone:     "example.com.",
			fqdn:     "_acme-challenge.example.com.",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			zone:     "sub.example.com.",
			fqdn:     "_acme-challenge.sub.example.com.",
			expected: "sub.example.com",
		},
		{
			name:     "no trailing dot",
			zone:     "example.com",
			fqdn:     "_acme-challenge.example.com",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processDomainName(tt.zone)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestTTLValidation tests TTL validation logic
func TestTTLValidation(t *testing.T) {
	tests := []struct {
		name     string
		inputTTL int
		expected int
	}{
		{
			name:     "valid TTL",
			inputTTL: 600,
			expected: 600,
		},
		{
			name:     "minimum TTL",
			inputTTL: 300,
			expected: 300,
		},
		{
			name:     "below minimum should use default",
			inputTTL: 100,
			expected: 300,
		},
		{
			name:     "zero should use default",
			inputTTL: 0,
			expected: 300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateTTL(tt.inputTTL)
			if result != tt.expected {
				t.Errorf("Expected TTL %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestSecretKeyExtraction tests secret key extraction logic
func TestSecretKeyExtraction(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"username": []byte("secretuser"),
			"password": []byte("secretpass"),
			"otpKey":   []byte("secretotp"),
		},
	}

	tests := []struct {
		name     string
		key      string
		expected string
		expectError bool
	}{
		{
			name:     "valid username key",
			key:      "username",
			expected: "secretuser",
		},
		{
			name:     "valid password key",
			key:      "password",
			expected: "secretpass",
		},
		{
			name:     "valid otp key",
			key:      "otpKey",
			expected: "secretotp",
		},
		{
			name:        "missing key",
			key:         "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractSecretKey(secret, tt.key)
			
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

			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestChallengeValidation tests challenge request validation
func TestChallengeValidation(t *testing.T) {
	tests := []struct {
		name        string
		challenge   *v1alpha1.ChallengeRequest
		expectError bool
	}{
		{
			name: "valid challenge",
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-key",
				ResourceNamespace: "test-namespace",
			},
		},
		{
			name: "missing zone",
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-key",
				ResourceNamespace: "test-namespace",
			},
			expectError: true,
		},
		{
			name: "missing fqdn",
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				Key:               "test-key",
				ResourceNamespace: "test-namespace",
			},
			expectError: true,
		},
		{
			name: "missing key",
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				ResourceNamespace: "test-namespace",
			},
			expectError: true,
		},
		{
			name: "missing namespace",
			challenge: &v1alpha1.ChallengeRequest{
				ResolvedZone: "example.com.",
				ResolvedFQDN: "_acme-challenge.example.com.",
				Key:          "test-key",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChallengeRequest(tt.challenge)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper functions for testing (these would be part of the actual implementation)

func validateCredentials(creds *credentials) error {
	if creds.Username == "" {
		return fmt.Errorf("username is required")
	}
	if creds.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

func processDomainName(zone string) string {
	// Remove trailing dot if present
	if len(zone) > 0 && zone[len(zone)-1] == '.' {
		return zone[:len(zone)-1]
	}
	return zone
}

func validateTTL(ttl int) int {
	if ttl < 300 {
		return 300 // Default TTL
	}
	return ttl
}

func extractSecretKey(secret *corev1.Secret, key string) (string, error) {
	if data, exists := secret.Data[key]; exists {
		return string(data), nil
	}
	return "", fmt.Errorf("key %s not found in secret", key)
}

func validateChallengeRequest(ch *v1alpha1.ChallengeRequest) error {
	if ch.ResolvedZone == "" {
		return fmt.Errorf("resolved zone is required")
	}
	if ch.ResolvedFQDN == "" {
		return fmt.Errorf("resolved FQDN is required")
	}
	if ch.Key == "" {
		return fmt.Errorf("challenge key is required")
	}
	if ch.ResourceNamespace == "" {
		return fmt.Errorf("resource namespace is required")
	}
	return nil
}

// Benchmark tests for performance
func BenchmarkConfigLoading(b *testing.B) {
	configJSON := `{"ttl": 600, "sandbox": true, "username": "testuser", "password": "testpass"}`
	jsonData := &extapi.JSON{Raw: []byte(configJSON)}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := loadConfig(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainNameProcessing(b *testing.B) {
	zone := "example.com."
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processDomainName(zone)
	}
} 