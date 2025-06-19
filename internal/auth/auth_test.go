package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedErr    error
	}{
		{
			name:           "no auth header", // Renamed for consistency
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Not Enough Parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedAPIKey: "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Wrong Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			expectedAPIKey: "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key_123"},
			},
			expectedAPIKey: "valid_api_key_123",
			expectedErr:    nil,
		},
		{
			name: "Valid Authorization Header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey   another_valid_key   "},
			},
			expectedAPIKey: "another_valid_key",
			expectedErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			// Assertion for API Key
			if apiKey != tt.expectedAPIKey {
				t.Errorf("GetAPIKey() got apiKey = %q, want %q", apiKey, tt.expectedAPIKey)
			}
			if tt.expectedErr == nil {
				if err != nil {
					t.Errorf("GetAPIKey() got err = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() got err = nil, want %v", tt.expectedErr)
				} else if err.Error() == tt.expectedErr.Error() {
				} else {
					t.Errorf("GetAPIKey() got err = %v (message: %q), want %v (message: %q)", err, err.Error(), tt.expectedErr, tt.expectedErr.Error())
				}
			}
		})
	}
}
