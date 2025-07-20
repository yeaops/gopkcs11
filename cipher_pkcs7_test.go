package gopkcs11

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPkcs11PaddingPKCS7(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "empty data with block size 16",
			data:      []byte{},
			blockSize: 16,
			expected:  []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
		{
			name:      "1 byte data with block size 16",
			data:      []byte{0x01},
			blockSize: 16,
			expected:  []byte{0x01, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
		},
		{
			name:      "15 bytes data with block size 16",
			data:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			blockSize: 16,
			expected:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1},
		},
		{
			name:      "16 bytes data with block size 16",
			data:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			blockSize: 16,
			expected:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
		{
			name:      "8 bytes data with block size 8",
			data:      []byte{1, 2, 3, 4, 5, 6, 7, 8},
			blockSize: 8,
			expected:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			name:      "3 bytes data with block size 8",
			data:      []byte{1, 2, 3},
			blockSize: 8,
			expected:  []byte{1, 2, 3, 5, 5, 5, 5, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pkcs11PaddingPKCS7(tt.data, tt.blockSize)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("pkcs11PaddingPKCS7() = %v, expected %v", result, tt.expected)
			}
			if len(result)%tt.blockSize != 0 {
				t.Errorf("pkcs11PaddingPKCS7() result length %d is not multiple of block size %d", len(result), tt.blockSize)
			}
		})
	}
}

func TestPkcs11UnpaddingPKCS7(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "valid padding - 16 bytes all padding",
			data:     []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "valid padding - 1 byte data with 15 padding",
			data:     []byte{0x01, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
			expected: []byte{0x01},
			wantErr:  false,
		},
		{
			name:     "valid padding - 15 bytes data with 1 padding",
			data:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1},
			expected: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantErr:  false,
		},
		{
			name:     "valid padding - 8 bytes padding",
			data:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
			expected: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantErr:  false,
		},
		{
			name:     "valid padding - 5 bytes padding",
			data:     []byte{1, 2, 3, 5, 5, 5, 5, 5},
			expected: []byte{1, 2, 3},
			wantErr:  false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "invalid padding - padding value larger than data length",
			data:     []byte{1, 2, 17},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "invalid padding - zero padding",
			data:     []byte{1, 2, 3, 0},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "invalid padding - inconsistent padding bytes",
			data:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 2},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "invalid padding - wrong padding byte value",
			data:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 3, 2},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pkcs11UnpaddingPKCS7(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("pkcs11UnpaddingPKCS7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(result, tt.expected) {
				t.Errorf("pkcs11UnpaddingPKCS7() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPkcs11PaddingUnpaddingRoundTrip(t *testing.T) {
	testData := [][]byte{
		{},
		{1},
		{1, 2, 3, 4, 5},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
	}

	blockSizes := []int{8, 16}

	for _, blockSize := range blockSizes {
		for i, data := range testData {
			t.Run(fmt.Sprintf("blockSize_%d_data_%d", blockSize, i), func(t *testing.T) {
				padded := pkcs11PaddingPKCS7(data, blockSize)
				unpadded, err := pkcs11UnpaddingPKCS7(padded)
				if err != nil {
					t.Errorf("Round trip failed for data %d with block size %d: %v", i, blockSize, err)
					return
				}
				if !bytes.Equal(data, unpadded) {
					t.Errorf("Round trip failed for data %d with block size %d: original=%v, result=%v", i, blockSize, data, unpadded)
				}
			})
		}
	}
}
