package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// testConfig represents the test configuration structure
type testConfig struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	OTPKey               string `json:"otpKey"`
	UsernameSecretKeyRef struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"usernameSecretKeyRef"`
	PasswordSecretKeyRef struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"passwordSecretKeyRef"`
	OTPKeySecretKeyRef struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"otpKeySecretKeyRef"`
	TTL     int  `json:"ttl,omitempty"`
	Sandbox bool `json:"sandbox,omitempty"`
}

var (
	zone      = "smueller18.de."
	zoneTwoFA = "smueller18mfa.de."

	testEnv *envtest.Environment
	cfg     *rest.Config
)

func TestMain(m *testing.M) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER") == "" || os.Getenv("INWX_USER") == "test-user" {
		fmt.Println("Skipping integration tests - no real INWX credentials provided")
		os.Exit(0)
	}

	if os.Getenv("TEST_ZONE_NAME") != "" {
		zone = os.Getenv("TEST_ZONE_NAME")
	}

	// Start test environment
	testEnv = &envtest.Environment{}
	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		panic(err)
	}

	code := m.Run()

	// Stop test environment
	if err := testEnv.Stop(); err != nil {
		panic(err)
	}

	os.Exit(code)
}

func TestSolver_Present(t *testing.T) {
	solver := &solver{}

	// Test basic configuration
	configData := testConfig{
		Username: os.Getenv("INWX_USER"),
		Password: os.Getenv("INWX_PASSWORD"),
		TTL:      300,
		Sandbox:  true,
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: zone,
		ResolvedFQDN: fmt.Sprintf("_acme-challenge.test.%s", zone),
		Key:          "test-key-value",
		Config: &extapi.JSON{
			Raw: configJSON,
		},
	}

	err = solver.Present(ch)
	if err != nil {
		t.Errorf("Expected Present to succeed, but got error: %v", err)
	}

	// Clean up
	err = solver.CleanUp(ch)
	if err != nil {
		t.Errorf("Expected CleanUp to succeed, but got error: %v", err)
	}
}

func TestSolver_PresentWithSecret(t *testing.T) {
	solver := &solver{}

	// Test with secret references (will fail in test environment but should not panic)
	configData := testConfig{
		UsernameSecretKeyRef: struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{
			Name: "inwx-credentials",
			Key:  "username",
		},
		PasswordSecretKeyRef: struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{
			Name: "inwx-credentials",
			Key:  "password",
		},
		TTL:     300,
		Sandbox: true,
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: zone,
		ResolvedFQDN: fmt.Sprintf("_acme-challenge.test-with-secret.%s", zone),
		Key:          "test-key-value",
		Config: &extapi.JSON{
			Raw: configJSON,
		},
	}

	// This will likely fail due to missing secret, but should not panic
	err = solver.Present(ch)
	if err == nil {
		// If it succeeds, clean up
		solver.CleanUp(ch)
	}
	// We don't fail the test here since secrets won't be available in test environment
}

func TestSolver_PresentWithTwoFA(t *testing.T) {
	if os.Getenv("INWX_USER_OTP") == "" || os.Getenv("INWX_USER_OTP") == "test-user-otp" {
		t.Skip("Skipping OTP tests - no real INWX OTP credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}

	solver := &solver{}

	configData := testConfig{
		Username: os.Getenv("INWX_USER_OTP"),
		Password: os.Getenv("INWX_PASSWORD_OTP"),
		OTPKey:   os.Getenv("INWX_TOTP_SECRET"),
		TTL:      300,
		Sandbox:  true,
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: zoneTwoFA,
		ResolvedFQDN: fmt.Sprintf("_acme-challenge.test-2fa.%s", zoneTwoFA),
		Key:          "test-key-value-2fa",
		Config: &extapi.JSON{
			Raw: configJSON,
		},
	}

	err = solver.Present(ch)
	if err != nil {
		t.Errorf("Expected Present with 2FA to succeed, but got error: %v", err)
	}

	// Clean up
	err = solver.CleanUp(ch)
	if err != nil {
		t.Errorf("Expected CleanUp with 2FA to succeed, but got error: %v", err)
	}
}

func TestSolver_PresentWithSecretAndTwoFA(t *testing.T) {
	if os.Getenv("INWX_USER_OTP") == "" || os.Getenv("INWX_USER_OTP") == "test-user-otp" {
		t.Skip("Skipping OTP tests - no real INWX OTP credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}

	solver := &solver{}

	// Test OTP with secret references
	configData := testConfig{
		UsernameSecretKeyRef: struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{
			Name: "inwx-credentials-otp",
			Key:  "username",
		},
		PasswordSecretKeyRef: struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{
			Name: "inwx-credentials-otp",
			Key:  "password",
		},
		OTPKeySecretKeyRef: struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{
			Name: "inwx-credentials-otp",
			Key:  "otpKey",
		},
		TTL:     300,
		Sandbox: true,
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: zoneTwoFA,
		ResolvedFQDN: fmt.Sprintf("_acme-challenge.test-secret-2fa.%s", zoneTwoFA),
		Key:          "test-key-value-secret-2fa",
		Config: &extapi.JSON{
			Raw: configJSON,
		},
	}

	// This will likely fail due to missing secret, but should not panic
	err = solver.Present(ch)
	if err == nil {
		// If it succeeds, clean up
		solver.CleanUp(ch)
	}
	// We don't fail the test here since secrets won't be available in test environment
}

func TestSolver_Name(t *testing.T) {
	solver := &solver{}
	name := solver.Name()

	if name != "inwx" {
		t.Errorf("Expected solver name to be 'inwx', got '%s'", name)
	}
}

func TestSolver_Timeout(t *testing.T) {
	// Test that the solver doesn't hang indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	solver := &solver{}

	configData := testConfig{
		Username: "test-user",
		Password: "test-password",
		TTL:      300,
		Sandbox:  true,
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: zone,
		ResolvedFQDN: fmt.Sprintf("_acme-challenge.timeout-test.%s", zone),
		Key:          "test-key-value",
		Config: &extapi.JSON{
			Raw: configJSON,
		},
	}

	done := make(chan error, 1)
	go func() {
		err := solver.Present(ch)
		done <- err
	}()

	select {
	case <-ctx.Done():
		t.Error("Solver.Present() took too long and timed out")
	case err := <-done:
		// Expected to fail with dummy credentials, but should not timeout
		if err == nil {
			t.Error("Expected Present to fail with dummy credentials")
		}
	}
}
