package sddl

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestSID_Binary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sid     *SID
		want    []byte
		wantErr error
	}{
		{
			name: "NULL SID (S-1-0-0)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 0,
				SubAuthority:        []uint32{0},
			},
			want: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authority (0 in big-endian)
				0x00, 0x00, 0x00, 0x00, // SubAuthority[0] = 0 in little-endian
			},
		},
		{
			name: "Well-known SID - Local System (S-1-5-18)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{18},
			},
			want: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (5 in big-endian)
				0x12, 0x00, 0x00, 0x00, // SubAuthority[0] = 18 in little-endian
			},
		},
		{
			name: "Well-known SID - BUILTIN\\Administrators (S-1-5-32-544)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{32, 544},
			},
			want: []byte{
				0x01,                               // Revision
				0x02,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (5 in big-endian)
				0x20, 0x00, 0x00, 0x00, // SubAuthority[0] = 32 in little-endian
				0x20, 0x02, 0x00, 0x00, // SubAuthority[1] = 544 in little-endian
			},
		},
		{
			name: "Maximum valid authority value (2^48-1)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: (1 << 48) - 1,
				SubAuthority:        []uint32{1},
			},
			want: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Authority (2^48-1 in big-endian)
				0x01, 0x00, 0x00, 0x00, // SubAuthority[0] = 1 in little-endian
			},
		},
		{
			name: "Maximum number of sub-authorities (15)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority: []uint32{
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				},
			},
			want: []byte{
				0x01,                               // Revision
				0x0F,                               // SubAuthorityCount (15)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority
				// SubAuthorities in little-endian
				0x01, 0x00, 0x00, 0x00, // 1
				0x02, 0x00, 0x00, 0x00, // 2
				0x03, 0x00, 0x00, 0x00, // 3
				0x04, 0x00, 0x00, 0x00, // 4
				0x05, 0x00, 0x00, 0x00, // 5
				0x06, 0x00, 0x00, 0x00, // 6
				0x07, 0x00, 0x00, 0x00, // 7
				0x08, 0x00, 0x00, 0x00, // 8
				0x09, 0x00, 0x00, 0x00, // 9
				0x0A, 0x00, 0x00, 0x00, // 10
				0x0B, 0x00, 0x00, 0x00, // 11
				0x0C, 0x00, 0x00, 0x00, // 12
				0x0D, 0x00, 0x00, 0x00, // 13
				0x0E, 0x00, 0x00, 0x00, // 14
				0x0F, 0x00, 0x00, 0x00, // 15
			},
		},

		// Error cases
		{
			name:    "Nil SID",
			sid:     nil,
			wantErr: fmt.Errorf("cannot convert nil SID to binary"),
		},
		{
			name: "Too many sub-authorities (16)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority: []uint32{
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				},
			},
			wantErr: ErrTooManySubAuthorities,
		},
		{
			name: "Authority value too large (2^48)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 1 << 48,
				SubAuthority:        []uint32{1},
			},
			wantErr: ErrInvalidAuthority,
		},
		{
			name: "Authority value way too large (2^63)",
			sid: &SID{
				Revision:            1,
				IdentifierAuthority: 1 << 63,
				SubAuthority:        []uint32{1},
			},
			wantErr: ErrInvalidAuthority,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable for parallel testing
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.sid.Binary()

			// Check error cases
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Binary() error = nil, wantErr = %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) && tt.wantErr.Error() != err.Error() {
					t.Errorf("Binary() error = %v, wantErr = %v", err, tt.wantErr)
				}
				if got != nil {
					t.Errorf("Binary() = %v, want nil when error", got)
				}
				return
			}

			// Check successful cases
			if err != nil {
				t.Errorf("Binary() unexpected error = %v", err)
				return
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("Binary() = %v, want %v", got, tt.want)

				// Detailed comparison for debugging
				if len(got) != len(tt.want) {
					t.Errorf("Binary() length = %d, want %d", len(got), len(tt.want))
				} else {
					for i := range got {
						if got[i] != tt.want[i] {
							t.Errorf("Binary() byte[%d] = 0x%02X, want 0x%02X",
								i, got[i], tt.want[i])
						}
					}
				}
			}
		})
	}
}
