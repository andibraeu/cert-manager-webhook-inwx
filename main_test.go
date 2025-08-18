package main

import (
	"context"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/acme/dns"
	"github.com/jetstack/cert-manager/test/acme/dns/server"
	"github.com/andibraeu/cert-manager-webhook-inwx/test"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"log"
	"os"
	"testing"
	"time"
)

var (
	zone      = "smueller18.de."
	zoneTwoFA = "smueller18mfa.de."
	fqdn      string
)

func TestRunSuite(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER") == "" || os.Getenv("INWX_USER") == "test-user" {
		t.Skip("Skipping API integration tests - no real INWX credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME") != "" {
		zone = os.Getenv("TEST_ZONE_NAME")
	}
	fqdn = "cert-manager-dns01-tests." + zone

	ctx := logf.NewContext(context.TODO(), nil, t.Name())

	srv := &server.BasicServer{
		Handler: &test.Handler{
			Log: logf.FromContext(ctx, "dnsBasicServer"),
			TxtRecords: map[string][][]string{
				fqdn: {
					{},
					{},
					{"123d=="},
					{"123d=="},
				},
			},
			Zones: []string{zone},
		},
	}

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	d, err := os.ReadFile("testdata/config.json")
	if err != nil {
		log.Fatal(err)
	}

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zone),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetBinariesPath("kubebuilder/bin"),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		// Set to false because INWX implementation deletes all records
		dns.SetStrict(false),
		dns.SetConfig(&extapi.JSON{
			Raw: d,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithSecret(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER") == "" || os.Getenv("INWX_USER") == "test-user" {
		t.Skip("Skipping API integration tests - no real INWX credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME") != "" {
		zone = os.Getenv("TEST_ZONE_NAME")
	}
	fqdn = "cert-manager-dns01-tests-with-secret." + zone

	ctx := logf.NewContext(context.TODO(), nil, t.Name())

	srv := &server.BasicServer{
		Handler: &test.Handler{
			Log: logf.FromContext(ctx, "dnsBasicServerSecret"),
			TxtRecords: map[string][][]string{
				fqdn: {
					{},
					{},
					{"123d=="},
					{"123d=="},
				},
			},
			Zones: []string{zone},
		},
	}

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	d, err := os.ReadFile("testdata/config.secret.json")
	if err != nil {
		log.Fatal(err)
	}

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zone),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetManifestPath("testdata/secret-inwx-credentials.yaml"),
		dns.SetBinariesPath("kubebuilder/bin"),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		dns.SetConfig(&extapi.JSON{
			Raw: d,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithTwoFA(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER_OTP") == "" || os.Getenv("INWX_USER_OTP") == "test-user-otp" {
		t.Skip("Skipping API integration tests - no real INWX OTP credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}

	fqdn = "cert-manager-dns01-tests." + zoneTwoFA

	ctx := logf.NewContext(context.TODO(), nil, t.Name())

	srv := &server.BasicServer{
		Handler: &test.Handler{
			Log: logf.FromContext(ctx, "dnsBasicServer"),
			TxtRecords: map[string][][]string{
				fqdn: {
					{},
					{},
					{"123d=="},
					{"123d=="},
				},
			},
			Zones: []string{zoneTwoFA},
		},
	}

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	d, err := os.ReadFile("testdata/config-otp.json")
	if err != nil {
		log.Fatal(err)
	}

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zoneTwoFA),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetBinariesPath("kubebuilder/bin"),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		// Set to false because INWX implementation deletes all records
		dns.SetStrict(false),
		dns.SetConfig(&extapi.JSON{
			Raw: d,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithSecretAndTwoFA(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER_OTP") == "" || os.Getenv("INWX_USER_OTP") == "test-user-otp" {
		t.Skip("Skipping API integration tests - no real INWX OTP credentials provided")
	}

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}
	fqdn = "cert-manager-dns01-tests-with-secret." + zoneTwoFA

	ctx := logf.NewContext(context.TODO(), nil, t.Name())

	srv := &server.BasicServer{
		Handler: &test.Handler{
			Log: logf.FromContext(ctx, "dnsBasicServerSecret"),
			TxtRecords: map[string][][]string{
				fqdn: {
					{},
					{},
					{"123d=="},
					{"123d=="},
				},
			},
			Zones: []string{zoneTwoFA},
		},
	}

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	d, err := os.ReadFile("testdata/config-otp.secret.json")
	if err != nil {
		log.Fatal(err)
	}

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zoneTwoFA),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetManifestPath("testdata/secret-inwx-credentials-otp.yaml"),
		dns.SetBinariesPath("kubebuilder/bin"),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		dns.SetConfig(&extapi.JSON{
			Raw: d,
		}),
	)

	fixture.RunConformance(t)
}
