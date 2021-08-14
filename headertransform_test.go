package header_transform_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	plug "github.com/adyanth/header-transform"
)

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	h := req.Header.Get(key)
	if h != expected {
		t.Errorf("invalid header value, got '%s', expect: '%s'", h, expected)
	}
}

func TestHeaderRules(t *testing.T) {
	tests := []struct {
		name    string
		rule    plug.InRule
		headers map[string]string
		want    map[string]string
		remote  string
	}{
		{
			name: "[Rename] no transformation",
			rule: plug.InRule{
				Type:   "Rename",
				Header: "not-existing",
			},
			headers: map[string]string{
				"Foo": "Bar",
			},
			want: map[string]string{
				"Foo": "Bar",
			},
		},
		{
			name: "[Rename] one transformation",
			rule: plug.InRule{
				Type:   "Rename",
				Header: "Test",
				Value:  "X-Testing",
			},
			headers: map[string]string{
				"Foo":  "Bar",
				"Test": "Success",
			},
			want: map[string]string{
				"Foo":       "Bar",
				"X-Testing": "Success",
			},
		},
		{
			name: "[Rename] Deletion",
			rule: plug.InRule{
				Type:   "Rename",
				Header: "Test",
			},
			headers: map[string]string{
				"Foo":  "Bar",
				"Test": "Success",
			},
			want: map[string]string{
				"Foo":  "Bar",
				"Test": "",
			},
		},
		{
			name: "[Set] Set one simple",
			rule: plug.InRule{
				Type:   "Set",
				Header: "X-Test",
				Value:  "Tested",
			},
			headers: map[string]string{
				"Foo": "Bar",
			},
			want: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Tested",
			},
		},
		{
			name: "[Set] Set already existing simple",
			rule: plug.InRule{
				Type:   "Set",
				Header: "X-Test",
				Value:  "Tested",
			},
			headers: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Bar",
			},
			want: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Tested", // Override
			},
		},
		{
			name: "[Del] Remove not existing header",
			rule: plug.InRule{
				Type:   "Del",
				Header: "X-Test",
			},
			headers: map[string]string{
				"Foo": "Bar",
			},
			want: map[string]string{
				"Foo": "Bar",
			},
		},
		{
			name: "[Del] Remove one header",
			rule: plug.InRule{
				Type:   "Del",
				Header: "X-Test",
			},
			headers: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Bar",
			},
			want: map[string]string{
				"Foo": "Bar",
			},
		},
		{
			name: "[Set] Join headers simple value (same as set)",
			rule: plug.InRule{
				Type:   "Set",
				Sep:    ",",
				Header: "X-Test",
				Values: []string{
					"Bar",
					"Tested",
				},
			},
			headers: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Old",
			},
			want: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Bar,Tested",
			},
		},
		{
			name: "[Set] Join two headers multiple value",
			rule: plug.InRule{
				Type:   "Set",
				Sep:    ",",
				Header: "X-Test",
				Values: []string{
					"Tested",
					"Compiled",
					"Working",
				},
			},
			headers: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Bar",
			},
			want: map[string]string{
				"Foo":    "Bar",
				"X-Test": "Tested,Compiled,Working",
			},
		},
		{
			name: "[Rename] no transformation with HeaderPrefix",
			rule: plug.InRule{
				Type:         "Rename",
				Header:       "not-existing",
				Value:        "^unused",
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo": "Bar",
			},
			want: map[string]string{
				"Foo": "Bar",
			},
		},
		{
			name: "[Rename] one transformation",
			rule: plug.InRule{
				Type:         "Rename",
				Header:       "Test",
				Value:        "^X-Dest-Header",
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":           "Bar",
				"Test":          "Success",
				"X-Dest-Header": "X-Testing",
			},
			want: map[string]string{
				"Foo":           "Bar",
				"X-Dest-Header": "X-Testing",
				"X-Testing":     "Success",
			},
		},
		{
			name: "[Set] new header from existing",
			rule: plug.InRule{
				Type:         "Set",
				Header:       "X-Test",
				Value:        "^X-Source",
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":      "Bar",
				"X-Source": "SourceHeader",
			},
			want: map[string]string{
				"Foo":      "Bar",
				"X-Source": "SourceHeader",
				"X-Test":   "SourceHeader",
			},
		},
		{
			name: "[Set] existing header from another existing",
			rule: plug.InRule{
				Type:         "Set",
				Header:       "X-Test",
				Value:        "^X-Source",
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":      "Bar",
				"X-Source": "SourceHeader",
				"X-Test":   "Initial",
			},
			want: map[string]string{
				"Foo":      "Bar",
				"X-Source": "SourceHeader",
				"X-Test":   "SourceHeader",
			},
		},
		{
			name: "[Set] Join two headers simple value",
			rule: plug.InRule{
				Type:   "Set",
				Sep:    ",",
				Header: "X-Test",
				Values: []string{
					"^X-Source",
				},
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":      "Bar",
				"X-Source": "Tested",
				"X-Test":   "Bar",
			},
			want: map[string]string{
				"Foo":      "Bar",
				"X-Source": "Tested",
				"X-Test":   "Tested",
			},
		},
		{
			name: "[Set] Join two headers multiple value",
			rule: plug.InRule{
				Type:   "Set",
				Sep:    ",",
				Header: "X-Test",
				Values: []string{
					"^X-Source-1",
					"Compiled",
					"^X-Source-3",
				},
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":        "Bar",
				"X-Test":     "Bar",
				"X-Source-1": "Tested",
				"X-Source-3": "Working",
			},
			want: map[string]string{
				"Foo":        "Bar",
				"X-Test":     "Tested,Compiled,Working",
				"X-Source-1": "Tested",
				"X-Source-3": "Working",
			},
		},
		{
			name: "[Set] Join two headers multiple value with itself",
			rule: plug.InRule{
				Type:   "Set",
				Sep:    ",",
				Header: "X-Test",
				Values: []string{
					"second",
					"^X-Test",
					"^X-Source-3",
				},
				HeaderPrefix: "^",
			},
			headers: map[string]string{
				"Foo":        "Bar",
				"X-Test":     "test",
				"X-Source-3": "third",
			},
			want: map[string]string{
				"Foo":    "Bar",
				"X-Test": "second,test,third",
			},
		},
		{
			name: "[TrustedCIDR] Check if headers are modified when IP is trusted",
			rule: plug.InRule{
				Type:   "Rename",
				Header: "Test",
				Value:  "X-Testing",
				TrustedCIDR: []string{
					"192.168.0.0/24",
				},
			},
			headers: map[string]string{
				"Foo":  "Bar",
				"Test": "Success",
			},
			want: map[string]string{
				"Foo":       "Bar",
				"X-Testing": "Success",
			},
			remote: "192.168.0.10:2200",
		},
		{
			name: "[TrustedCIDR] Check if headers are not modified when IP is not trusted",
			rule: plug.InRule{
				Type:   "Rename",
				Header: "Test",
				Value:  "X-Testing",
				TrustedCIDR: []string{
					"192.168.1.0/24",
				},
			},
			headers: map[string]string{
				"Foo":  "Bar",
				"Test": "Success",
			},
			want: map[string]string{
				"Foo":  "Bar",
				"Test": "Success",
			},
			remote: "192.168.0.10:2200",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := plug.CreateConfig()
			cfg.Rules = []plug.InRule{tt.rule}

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			handler, err := plug.New(ctx, next, cfg, "demo-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if tt.remote == "" {
				tt.remote = "10.10.10.1:2000"
			}
			req.RemoteAddr = tt.remote
			if err != nil {
				t.Fatal(err)
			}

			for hName, hVal := range tt.headers {
				req.Header.Add(hName, hVal)
			}

			handler.ServeHTTP(recorder, req)

			for hName, hVal := range tt.want {
				assertHeader(t, req, hName, hVal)
			}
		})
	}
}
