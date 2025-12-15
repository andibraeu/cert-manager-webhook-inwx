package internal

import (
	"context"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/nrdcg/goinwx"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockDNSClient is a mock implementation of DNSClient for testing
type MockDNSClient struct {
	LoginError        error
	LogoutError       error
	CreateRecordError error
	InfoRecordsError  error
	DeleteRecordError error
	UnlockError       error

	Records          map[string]*goinwx.NameserverRecord
	LoginCalled      bool
	LogoutCalled     bool
	UnlockCalled     bool
	CreatedRecords   []*goinwx.NameserverRecordRequest
	DeletedRecordIDs []string
}

func NewMockDNSClient() *MockDNSClient {
	return &MockDNSClient{
		Records:          make(map[string]*goinwx.NameserverRecord),
		CreatedRecords:   make([]*goinwx.NameserverRecordRequest, 0),
		DeletedRecordIDs: make([]string, 0),
	}
}

func (m *MockDNSClient) Login() error {
	m.LoginCalled = true
	return m.LoginError
}

func (m *MockDNSClient) Logout() error {
	m.LogoutCalled = true
	return m.LogoutError
}

func (m *MockDNSClient) CreateRecord(request *goinwx.NameserverRecordRequest) error {
	if m.CreateRecordError != nil {
		return m.CreateRecordError
	}

	m.CreatedRecords = append(m.CreatedRecords, request)

	// Create a mock record
	recordID := len(m.Records) + 1
	key := fmt.Sprintf("%s-%s", request.Domain, request.Name)
	m.Records[key] = &goinwx.NameserverRecord{
		ID:      fmt.Sprintf("%d", recordID),
		Name:    request.Name,
		Type:    request.Type,
		Content: request.Content,
		TTL:     request.TTL,
	}

	return nil
}

func (m *MockDNSClient) InfoRecords(request *goinwx.NameserverInfoRequest) (*NameserverInfoResponse, error) {
	if m.InfoRecordsError != nil {
		return nil, m.InfoRecordsError
	}

	var records []goinwx.NameserverRecord
	key := fmt.Sprintf("%s-%s", request.Domain, request.Name)

	if record, exists := m.Records[key]; exists {
		records = append(records, *record)
	}

	return &NameserverInfoResponse{
		Records: records,
	}, nil
}

func (m *MockDNSClient) DeleteRecord(recordID string) error {
	if m.DeleteRecordError != nil {
		return m.DeleteRecordError
	}

	m.DeletedRecordIDs = append(m.DeletedRecordIDs, recordID)

	// Find and remove the record
	for key, record := range m.Records {
		if record.ID == recordID {
			delete(m.Records, key)
			break
		}
	}

	return nil
}

func (m *MockDNSClient) UnlockAccount(otpKey string) error {
	m.UnlockCalled = true
	return m.UnlockError
}

// MockSecretReader is a mock implementation of SecretReader for testing
type MockSecretReader struct {
	Secrets map[string]*corev1.Secret
	Error   error
}

func NewMockSecretReader() *MockSecretReader {
	return &MockSecretReader{
		Secrets: make(map[string]*corev1.Secret),
	}
}

func (m *MockSecretReader) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	if m.Error != nil {
		return nil, m.Error
	}

	key := fmt.Sprintf("%s/%s", namespace, name)
	if secret, exists := m.Secrets[key]; exists {
		return secret, nil
	}

	return nil, fmt.Errorf("secret %s not found", key)
}

func (m *MockSecretReader) AddSecret(namespace, name string, data map[string][]byte) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	m.Secrets[key] = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

// MockConfigProvider is a mock implementation of ConfigProvider for testing
type MockConfigProvider struct {
	Config *Config
	Error  error
}

func NewMockConfigProvider(config *Config) *MockConfigProvider {
	return &MockConfigProvider{
		Config: config,
	}
}

func (m *MockConfigProvider) LoadConfig(ch *v1alpha1.ChallengeRequest) (*Config, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Config, nil
}
