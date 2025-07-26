package pipeline

import (
	"os"
	"testing"
)

func TestNormalize_Expanded(t *testing.T) {
	tests := []struct {
		name    string
		input   string // raw JSON for rawFingerprints
		wantErr bool
	}{
		{
			name:    "valid minimal input",
			input:   `{"apps": {"TestApp": {"html": ["abc"]}}}`,
			wantErr: false,
		},
		{
			name:    "missing apps key",
			input:   `{}`,
			wantErr: false, // Should not error, just empty
		},
		{
			name:    "invalid JSON",
			input:   `{"apps": {"TestApp": {"html": [abc]}}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/file", func(t *testing.T) {
			// Write input to temp file
			tmpfile, err := os.CreateTemp("", "normalize_test_*.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpfile.Name())
			_, err = tmpfile.Write([]byte(tt.input))
			tmpfile.Close()
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			_, err = Normalize(tmpfile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("Normalize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
		t.Run(tt.name+"/bytes", func(t *testing.T) {
			_, err := NormalizeFromBytes([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
