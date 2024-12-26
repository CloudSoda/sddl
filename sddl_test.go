package sddl

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestParseSIDBinary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "Invalid data - too short",
			data:    []byte{0x01, 0x02}, // Not enough bytes for a valid SID
			want:    "",
			wantErr: true,
		},
		{
			name:    "Invalid data - nil",
			data:    nil,
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid data - mismatched length for sub-authorities",
			data: []byte{
				0x01,                               // Revision
				0x02,                               // SubAuthorityCount (claims 2 but only has data for 1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x01, 0x00, 0x00, 0x00, // One SubAuthority only
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Valid minimal SID",
			data: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (NT Authority)
				0x01, 0x00, 0x00, 0x00, // SubAuthority[0] = 1 (DIALUP)
			},
			want:    "DU", // Well-known SID for DIALUP
			wantErr: false,
		},
		{
			name: "Valid SID with multiple authorities",
			data: []byte{
				0x01,                               // Revision
				0x02,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (NT Authority)
				0x20, 0x00, 0x00, 0x00, // SubAuthority[0] = 32 (BUILTIN)
				0x20, 0x02, 0x00, 0x00, // SubAuthority[1] = 544 (Administrators)
			},
			want:    "BA", // Well-known SID for BUILTIN\Administrators
			wantErr: false,
		},
		{
			name: "Non-well-known SID",
			data: []byte{
				0x01,                               // Revision
				0x05,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x21, 0x00, 0x00, 0x00, // SubAuthority[0]
				0x22, 0x00, 0x00, 0x00, // SubAuthority[1]
				0x23, 0x00, 0x00, 0x00, // SubAuthority[2]
				0x24, 0x00, 0x00, 0x00, // SubAuthority[3]
				0x25, 0x00, 0x00, 0x00, // SubAuthority[4]
			},
			want:    "S-1-5-33-34-35-36-37", // Regular SID format
			wantErr: false,
		},
		{
			name: "Well-known NT AUTHORITY\\SYSTEM SID",
			data: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (NT Authority)
				0x12, 0x00, 0x00, 0x00, // SubAuthority[0] = 18 (SYSTEM)
			},
			want:    "SY", // Well-known SID for Local System
			wantErr: false,
		},
		{
			name: "Well-known Everyone SID",
			data: []byte{
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // World Authority
				0x00, 0x00, 0x00, 0x00, // SubAuthority[0] = 0
			},
			want:    "WD", // Well-known SID for Everyone
			wantErr: false,
		},
		{
			name: "Maximum sub-authorities",
			data: []byte{
				0x01,                               // Revision
				0x0F,                               // SubAuthorityCount (15 is max)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x01, 0x00, 0x00, 0x00, // SubAuthority[0]
				0x02, 0x00, 0x00, 0x00,
				0x03, 0x00, 0x00, 0x00,
				0x04, 0x00, 0x00, 0x00,
				0x05, 0x00, 0x00, 0x00,
				0x06, 0x00, 0x00, 0x00,
				0x07, 0x00, 0x00, 0x00,
				0x08, 0x00, 0x00, 0x00,
				0x09, 0x00, 0x00, 0x00,
				0x0A, 0x00, 0x00, 0x00,
				0x0B, 0x00, 0x00, 0x00,
				0x0C, 0x00, 0x00, 0x00,
				0x0D, 0x00, 0x00, 0x00,
				0x0E, 0x00, 0x00, 0x00,
				0x0F, 0x00, 0x00, 0x00,
			},
			want:    "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
			wantErr: false,
		},
		{
			name: "Too many sub-authorities",
			data: []byte{
				0x01,                               // Revision
				0x10,                               // SubAuthorityCount (16 is too many)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x01, 0x00, 0x00, 0x00, // SubAuthority data...
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sid, err := parseSIDBinary(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSIDToStruct() error = %v, wantErr %v", err, tt.wantErr)
				}
				if sid != nil {
					t.Errorf("parseSIDToStruct() sid = %#v, want nil", sid)
				}
				return
			}

			if err != nil {
				t.Errorf("parseSIDToStruct() error = %v, wantErr %v", err, tt.wantErr)
			}

			if sid == nil {
				t.Errorf("parseSIDToStruct() sid = nil, want non-nil, wantErr %v", tt.wantErr)
				return
			}

			if sidStr := sid.String(); sidStr != tt.want {
				t.Errorf("parseSIDToStruct() = %v, want %v, (sid = %#v)", sidStr, tt.want, sid)
			}
		})
	}
}

func TestParseSIDString(t *testing.T) {
	// Test high authority values close to boundary conditions
	maxAuthority := uint64(1<<48 - 1)

	tests := []struct {
		name    string
		input   string
		want    *SID
		wantErr error
	}{
		{
			name:  "Well-known SID short form (SYSTEM)",
			input: "SY",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{18},
			},
		},
		{
			name:  "Well-known SID full form (SYSTEM)",
			input: "S-1-5-18",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{18},
			},
		},
		{
			name:  "Complex SID",
			input: "S-1-5-21-3623811015-3361044348-30300820-1013",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{21, 3623811015, 3361044348, 30300820, 1013},
			},
		},
		{
			name:  "Minimum valid SID",
			input: "S-1-0-0",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 0,
				SubAuthority:        []uint32{0},
			},
		},
		{
			name:  "Maximum sub-authorities",
			input: "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
			},
		},
		{
			name:    "Invalid format - no S- prefix",
			input:   "1-5-18",
			wantErr: ErrInvalidSIDFormat,
		},
		{
			name:    "Invalid format - empty string",
			input:   "",
			wantErr: ErrInvalidSIDFormat,
		},
		{
			name:    "Invalid format - missing components",
			input:   "S-1",
			wantErr: ErrInvalidSIDFormat,
		},
		{
			name:    "Invalid revision",
			input:   "S-2-5-18",
			wantErr: ErrInvalidRevision,
		},
		{
			name:    "Invalid revision - not a number",
			input:   "S-X-5-18",
			wantErr: ErrInvalidRevision,
		},
		{
			name:    "Invalid authority - not a number",
			input:   "S-1-X-18",
			wantErr: ErrInvalidAuthority,
		},
		{
			name:    "Invalid sub-authority - not a number",
			input:   "S-1-5-X",
			wantErr: ErrInvalidSubAuthority,
		},
		{
			name:    "Too many sub-authorities",
			input:   "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
			wantErr: ErrTooManySubAuthorities,
		},
		{
			name:  "High authority value in hex",
			input: "S-1-0xFFFFFFFF0000-1-2",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 0xFFFFFFFF0000,
				SubAuthority:        []uint32{1, 2},
			},
		},
		{
			name:  "Authority value just below 2^32 in decimal",
			input: "S-1-4294967295-1-2",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 4294967295,
				SubAuthority:        []uint32{1, 2},
			},
		},
		{
			name:  "Authority value maximum (2^48-1) in hex",
			input: fmt.Sprintf("S-1-0x%X-1-2", maxAuthority),
			want: &SID{
				Revision:            1,
				IdentifierAuthority: maxAuthority,
				SubAuthority:        []uint32{1, 2},
			},
		},
		{
			name:    "Authority value too large in hex",
			input:   "S-1-0x1000000000000-1-2", // 2^48
			wantErr: ErrInvalidAuthority,
		},
		{
			name:    "Invalid hex authority format - bad characters",
			input:   "S-1-0xGHIJKL-1-2",
			wantErr: ErrInvalidAuthority,
		},
		{
			name:    "Invalid hex authority format - missing digits",
			input:   "S-1-0x-1-2",
			wantErr: ErrInvalidAuthority,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable for parallel execution
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // Enable parallel execution

			got, err := parseSIDString(tt.input)

			if tt.wantErr != nil {
				if got != nil {
					t.Error("parseSIDString() returned non-nil SID when error was expected")
				}
				if err == nil {
					t.Errorf("parseSIDString() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("parseSIDString() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("parseSIDString() unexpected error = %v", err)
				return
			}

			if got == nil {
				t.Error("parseSIDString() returned nil SID when success was expected")
				return
			}

			if got.Revision != tt.want.Revision {
				t.Errorf("Revision = %v, want %v", got.Revision, tt.want.Revision)
			}
			if got.IdentifierAuthority != tt.want.IdentifierAuthority {
				t.Errorf("IdentifierAuthority = %v, want %v",
					got.IdentifierAuthority, tt.want.IdentifierAuthority)
			}
			if len(got.SubAuthority) != len(tt.want.SubAuthority) {
				t.Errorf("SubAuthority length = %v, want %v",
					len(got.SubAuthority), len(tt.want.SubAuthority))
			} else {
				for i := range got.SubAuthority {
					if got.SubAuthority[i] != tt.want.SubAuthority[i] {
						t.Errorf("SubAuthority[%d] = %v, want %v",
							i, got.SubAuthority[i], tt.want.SubAuthority[i])
					}
				}
			}
		})
	}
}

func TestParseACEBinary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "Invalid data - too short",
			data:    []byte{0x00, 0x00, 0x14, 0x00}, // Only header size, no mask or SID
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid data - mismatched size",
			data: []byte{
				0x00,       // Type
				0x00,       // Flags
				0xFF, 0x00, // Size (larger than actual data)
				0x00, 0x00, 0x00, 0x00, // Mask
				// Minimal SID
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Basic Allow ACE",
			data: []byte{
				// ACE Header
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags (none)
				0x14, 0x00, // Size (20 bytes)
				// Access mask
				0xFF, 0x01, 0x1F, 0x00, // 0x1F01FF - Full Access
				// SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
			want:    "(A;;FA;;;SY)",
			wantErr: false,
		},
		{
			name: "Basic Deny ACE",
			data: []byte{
				0x01,       // Type (ACCESS_DENIED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size
				0x89, 0x00, 0x12, 0x00, // 0x120089 - File Read
				// SID (Everyone)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
			},
			want:    "(D;;FR;;;WD)",
			wantErr: false,
		},
		{
			name: "Audit ACE",
			data: []byte{
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x00,       // Flags
				0x18, 0x00, // Size
				0x16, 0x01, 0x12, 0x00, // 0x120116 - File Write
				// SID (BUILTIN\Administrators)
				0x01, 0x02,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x20, 0x00, 0x00, 0x00,
				0x20, 0x02, 0x00, 0x00,
			},
			want:    "(AU;;WR;;;BA)",
			wantErr: false,
		},
		{
			name: "ACE with inheritance flags",
			data: []byte{
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x0B,       // Flags (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)
				0x14, 0x00, // Size
				0xA9, 0x00, 0x12, 0x00, // 0x1200A9 - Read and Execute Access
				// SID (Authenticated Users)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x0B, 0x00, 0x00, 0x00,
			},
			want:    "(A;OICIIO;RA;;;AU)",
			wantErr: false,
		},
		{
			name: "ACE with custom access mask",
			data: []byte{
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size
				0x34, 0x12, 0x56, 0x78, // Custom access mask
				// SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
			want:    "(A;;0x78561234;;;SY)",
			wantErr: false,
		},
		{
			name: "ACE with inherited flag",
			data: []byte{
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x10,       // Flags (INHERITED_ACE)
				0x18, 0x00, // Size
				0x89, 0x00, 0x12, 0x00, // File Read
				// SID (BUILTIN\Users)
				0x01, 0x02,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x20, 0x00, 0x00, 0x00,
				0x21, 0x02, 0x00, 0x00,
			},
			want:    "(A;ID;FR;;;BU)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ace, err := parseACEBinary(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseACEToStruct() expected error, got nil")
				}
				if ace != nil {
					t.Errorf("parseACEToStruct() expected nil, got %v", ace)
				}
				return
			}

			if err != nil {
				t.Errorf("parseACEToStruct() error = %v, expected nil", err)
				return
			}

			if ace == nil {
				t.Errorf("parseACEToStruct() expected non-nil, got nil")
				return
			}

			aceStr := ace.String()
			if aceStr != tt.want {
				t.Errorf("parseACEToStruct() = %v, want %v", aceStr, tt.want)
			}
		})
	}
}

func TestParseACEString(t *testing.T) {
	// Helper function to create a SID for testing
	createTestSID := func(revision byte, authority uint64, subAuth ...uint32) *SID {
		return &SID{
			Revision:            revision,
			IdentifierAuthority: authority,
			SubAuthority:        subAuth,
		}
	}

	tests := []struct {
		name    string
		aceStr  string
		want    *ACE
		wantErr bool
	}{
		{
			name:   "Basic allow ACE",
			aceStr: "(A;;FA;;;SY)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: 0,
					AceSize:  20, // 4 (header) + 4 (mask) + 12 (SID with 1 sub-authority)
				},
				AccessMask: 0x1F01FF,                // FA - Full Access
				SID:        createTestSID(1, 5, 18), // SY - Local System
			},
			wantErr: false,
		},
		{
			name:   "Deny ACE with inheritance flags",
			aceStr: "(D;OICI;FR;;;BA)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_DENIED_ACE_TYPE,
					AceFlags: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
					AceSize:  24, // 4 (header) + 4 (mask) + 16 (SID with 2 sub-authorities)
				},
				AccessMask: 0x120089,                     // FR - File Read
				SID:        createTestSID(1, 5, 32, 544), // BA - Builtin Administrators
			},
			wantErr: false,
		},
		{
			name:   "Audit ACE with success audit",
			aceStr: "(AU;SA;FA;;;WD)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  SYSTEM_AUDIT_ACE_TYPE,
					AceFlags: SUCCESSFUL_ACCESS_ACE,
					AceSize:  20, // 4 (header) + 4 (mask) + 12 (SID with 1 sub-authority)
				},
				AccessMask: 0x1F01FF,               // FA
				SID:        createTestSID(1, 1, 0), // WD - Everyone
			},
			wantErr: false,
		},
		{
			name:   "Audit ACE with both success and failure",
			aceStr: "(AU;SAFA;FA;;;SY)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  SYSTEM_AUDIT_ACE_TYPE,
					AceFlags: SUCCESSFUL_ACCESS_ACE | FAILED_ACCESS_ACE,
					AceSize:  20,
				},
				AccessMask: 0x1F01FF,
				SID:        createTestSID(1, 5, 18),
			},
			wantErr: false,
		},
		{
			name:   "Complex inheritance flags",
			aceStr: "(A;OICIIONP;FA;;;AU)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | NO_PROPAGATE_INHERIT_ACE,
					AceSize:  20,
				},
				AccessMask: 0x1F01FF,
				SID:        createTestSID(1, 5, 11), // AU - Authenticated Users
			},
			wantErr: false,
		},
		{
			name:   "Directory operations access mask",
			aceStr: "(A;;DCLCRPCR;;;SY)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: 0,
					AceSize:  20, // 4 (header) + 4 (access mask) + 12 (SID with 1 sub-authority)
				},
				AccessMask: 0x000116, // Directory Create/List/Read/Pass through/Child rename/Child delete
				SID:        createTestSID(1, 5, 18),
			},
			wantErr: false,
		},
		{
			name:   "Custom access mask",
			aceStr: "(A;;0x1234ABCD;;;SY)",
			want: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: 0,
					AceSize:  20, // 4 (header) + 4 (mask) + 12 (SID with 1 sub-authority)
				},
				AccessMask: 0x1234ABCD,
				SID:        createTestSID(1, 5, 18),
			},
			wantErr: false,
		},
		{
			name:   "Custom ACE type",
			aceStr: "(0x15;;FA;;;SY)", // SYSTEM_ACCESS_FILTER_ACE_TYPE
			want: &ACE{
				Header: &ACEHeader{
					AceType:  0x15,
					AceFlags: 0,
					AceSize:  20, // 4 (header) + 4 (access mask) + 12 (SID with 1 sub-authority)
				},
				AccessMask: 0x1F01FF,
				SID:        createTestSID(1, 5, 18),
			},
			wantErr: false,
		},
		// Error cases
		{
			name:    "Invalid format - missing parentheses",
			aceStr:  "A;;FA;;;SY",
			wantErr: true,
		},
		{
			name:    "Invalid format - wrong number of components",
			aceStr:  "(A;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Invalid ACE type",
			aceStr:  "(X;;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Invalid hex ACE type",
			aceStr:  "(0xZZ;;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Invalid flags format",
			aceStr:  "(A;OIC;FA;;;SY)", // Incomplete flag pair
			wantErr: true,
		},
		{
			name:    "Unknown flag",
			aceStr:  "(A;XXXX;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Audit flags on non-audit ACE",
			aceStr:  "(A;SAFA;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Audit ACE without audit flags",
			aceStr:  "(AU;OICI;FA;;;SY)",
			wantErr: true,
		},
		{
			name:    "Invalid access mask",
			aceStr:  "(A;;XX;;;SY)",
			wantErr: true,
		},
		{
			name:    "Invalid hex access mask",
			aceStr:  "(A;;0xZZZZ;;;SY)",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseACEString(tt.aceStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseACEString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Compare Header fields
			if got.Header.AceType != tt.want.Header.AceType {
				t.Errorf("ACE Type = %v, want %v", got.Header.AceType, tt.want.Header.AceType)
			}
			if got.Header.AceFlags != tt.want.Header.AceFlags {
				t.Errorf("ACE Flags = %v, want %v", got.Header.AceFlags, tt.want.Header.AceFlags)
			}
			if got.Header.AceSize != tt.want.Header.AceSize {
				t.Errorf("ACE Size = %v, want %v", got.Header.AceSize, tt.want.Header.AceSize)
			}

			// Compare AccessMask
			if got.AccessMask != tt.want.AccessMask {
				t.Errorf("AccessMask = %v, want %v", got.AccessMask, tt.want.AccessMask)
			}

			// Compare SID fields
			if got.SID.Revision != tt.want.SID.Revision {
				t.Errorf("SID Revision = %v, want %v", got.SID.Revision, tt.want.SID.Revision)
			}
			if got.SID.IdentifierAuthority != tt.want.SID.IdentifierAuthority {
				t.Errorf("SID Authority = %v, want %v", got.SID.IdentifierAuthority, tt.want.SID.IdentifierAuthority)
			}
			if !reflect.DeepEqual(got.SID.SubAuthority, tt.want.SID.SubAuthority) {
				t.Errorf("SID SubAuthority = %v, want %v", got.SID.SubAuthority, tt.want.SID.SubAuthority)
			}
		})
	}
}

func TestParseACLBinary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		aclType string
		control uint16
		want    string
		wantErr bool
	}{
		{
			name:    "Invalid data - too short",
			data:    []byte{0x02, 0x00}, // Not enough bytes for ACL header
			aclType: "D",
			control: 0,
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid data - size mismatch",
			data: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0xFF, 0x00, // Size (too large)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
			},
			aclType: "D",
			control: 0,
			want:    "",
			wantErr: true,
		},
		{
			name: "Empty ACL",
			data: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0x08, 0x00, // Size (8 bytes - just header)
				0x00, 0x00, // AceCount
				0x00, 0x00, // Sbz2
			},
			aclType: "D",
			control: 0,
			want:    "D:",
			wantErr: false,
		},
		{
			name: "Protected empty ACL",
			data: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0x08, 0x00, // Size
				0x00, 0x00, // AceCount
				0x00, 0x00, // Sbz2
			},
			aclType: "D",
			control: SE_DACL_PROTECTED,
			want:    "D:P",
			wantErr: false,
		},
		{
			name: "Auto-inherited empty ACL",
			data: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0x08, 0x00, // Size
				0x00, 0x00, // AceCount
				0x00, 0x00, // Sbz2
			},
			aclType: "D",
			control: SE_DACL_AUTO_INHERITED,
			want:    "D:AI",
			wantErr: false,
		},
		{
			name: "Protected and auto-inherited empty ACL",
			data: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0x08, 0x00, // Size
				0x00, 0x00, // AceCount
				0x00, 0x00, // Sbz2
			},
			aclType: "D",
			control: SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
			want:    "D:PAI",
			wantErr: false,
		},
		{
			name: "ACL with one ACE",
			data: []byte{
				// ACL Header
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes = 8 header + 20 ACE)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				// SID (SYSTEM)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority
				0x12, 0x00, 0x00, 0x00, // SubAuthority
			},
			aclType: "D",
			control: 0,
			want:    "D:(A;;FA;;;SY)",
			wantErr: false,
		},
		{
			name: "ACL with multiple ACEs",
			data: []byte{
				// ACL Header
				0x02,       // Revision
				0x00,       // Sbz1
				0x38, 0x00, // Size (56 bytes = 8 header + 20 first ACE + 28 second ACE)
				0x02, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// First ACE - Allow System Full Access
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01, // SID
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00, // SYSTEM
				// Second ACE - Allow Administrators Read
				0x00,       // Type
				0x00,       // Flags
				0x18, 0x00, // Size (24 bytes - larger to accommodate full Administrators SID)
				0x89, 0x00, 0x12, 0x00, // Access mask (File Read)
				0x01, 0x02, // SID: Rev=1, Count=2
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x20, 0x00, 0x00, 0x00, // SubAuth1 = 32 (BUILTIN)
				0x20, 0x02, 0x00, 0x00, // SubAuth2 = 544 (Administrators)
			},
			aclType: "D",
			control: 0,
			want:    "D:(A;;FA;;;SY)(A;;FR;;;BA)",
			wantErr: false,
		},
		{
			name: "SACL with audit ACEs",
			data: []byte{
				// ACL Header
				0x02,       // Revision
				0x00,       // Sbz1
				0x28, 0x00, // Size (40 bytes = 8 header + 2 ACEs of 16 bytes each)
				0x02, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// First ACE - Audit System Success
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x40,       // Flags (SUCCESSFUL_ACCESS_ACE)
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00, // SYSTEM
				// Second ACE - Audit System Failure
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x80,       // Flags (FAILED_ACCESS_ACE)
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00, // SYSTEM
			},
			aclType: "S",
			control: SE_SACL_PRESENT,
			want:    "S:(AU;SA;FA;;;SY)(AU;FA;FA;;;SY)",
			wantErr: false,
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			acl, err := parseACLBinary(tt.data, tt.aclType, tt.control)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseACLToStruct() = %v, wantErr %v", acl, tt.wantErr)
				}
				if acl != nil {
					t.Errorf("parseACLToStruct() = %v, wantErr %v", acl, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("parseACLToStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if acl == nil {
				t.Errorf("parseACLToStruct() = %v, wantErr %v", acl, tt.wantErr)
				return
			}

			aclStr := acl.String()

			if aclStr != tt.want {
				t.Errorf("parseACLToStruct() = %v, want %v", aclStr, tt.want)
			}
		})
	}
}

func TestParseSecurityDescriptorBinary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "Invalid data - too short",
			data:    []byte{0x01, 0x00, 0x04},
			want:    "",
			wantErr: true,
		},
		{
			name:    "Invalid data - nil",
			data:    nil,
			want:    "",
			wantErr: true,
		},
		{
			name: "Empty self-relative security descriptor",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x00, 0x80, // Control (SE_SELF_RELATIVE)
				0x00, 0x00, 0x00, 0x00, // Owner
				0x00, 0x00, 0x00, 0x00, // Group
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x00, 0x00, 0x00, 0x00, // Dacl
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "Security descriptor with owner only",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x00, 0x80, // Control (SE_SELF_RELATIVE)
				0x14, 0x00, 0x00, 0x00, // Owner offset
				0x00, 0x00, 0x00, 0x00, // Group
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x00, 0x00, 0x00, 0x00, // Dacl
				// Owner SID (SYSTEM)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority
				0x12, 0x00, 0x00, 0x00, // SubAuthority
			},
			want:    "O:SY",
			wantErr: false,
		},
		{
			name: "Security descriptor with owner and group",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x00, 0x80, // Control (SE_SELF_RELATIVE)
				0x14, 0x00, 0x00, 0x00, // Owner offset (20 bytes from start)
				0x20, 0x00, 0x00, 0x00, // Group offset (32 bytes from start)
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x00, 0x00, 0x00, 0x00, // Dacl
				// Owner SID (SYSTEM)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority
				0x12, 0x00, 0x00, 0x00, // SubAuthority
				// Group SID (Everyone - S-1-1-0)
				0x01,                               // Revision (1)
				0x01,                               // SubAuthorityCount (1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority (SECURITY_WORLD_SID_AUTHORITY = 1)
				0x00, 0x00, 0x00, 0x00, // SubAuthority[0] = 0 (final component of S-1-1-0)
				// Owner SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
				// Group SID (Everyone)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
			},
			want:    "O:SYG:WD",
			wantErr: false,
		},
		{
			name: "Security descriptor with DACL",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x04, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT)
				0x00, 0x00, 0x00, 0x00, // Owner
				0x00, 0x00, 0x00, 0x00, // Group
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x14, 0x00, 0x00, 0x00, // Dacl offset
				// DACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				// SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
			want:    "D:(A;;FA;;;SY)",
			wantErr: false,
		},
		{
			name: "Security descriptor with SACL",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x10, 0x80, // Control (SE_SELF_RELATIVE | SE_SACL_PRESENT)
				0x00, 0x00, 0x00, 0x00, // Owner
				0x00, 0x00, 0x00, 0x00, // Group
				0x14, 0x00, 0x00, 0x00, // Sacl offset
				0x00, 0x00, 0x00, 0x00, // Dacl
				// SACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// ACE
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x40,       // Flags (SUCCESSFUL_ACCESS_ACE)
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				// SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
			want:    "S:(AU;SA;FA;;;SY)",
			wantErr: false,
		},
		{
			name: "Complete security descriptor with all components",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x14, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT)
				0x4C, 0x00, 0x00, 0x00, // Owner offset
				0x58, 0x00, 0x00, 0x00, // Group offset
				0x14, 0x00, 0x00, 0x00, // Sacl offset
				0x30, 0x00, 0x00, 0x00, // Dacl offset
				// SACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// SACL ACE
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x40,       // Flags (SUCCESSFUL_ACCESS_ACE)
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (NT)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
				// DACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// DACL ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (NT)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
				// Owner SID (SYSTEM)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (NT)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
				// Group SID (Everyone)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Authority (WORLD)
				0x00, 0x00, 0x00, 0x00, // SubAuthority (0)
			},
			want:    "O:SYG:WDD:(A;;FA;;;SY)S:(AU;SA;FA;;;SY)",
			wantErr: false,
		},
		{
			name: "Invalid owner offset",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x00, 0x80, // Control
				0xFF, 0xFF, 0xFF, 0xFF, // Owner (invalid offset)
				0x00, 0x00, 0x00, 0x00, // Group
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x00, 0x00, 0x00, 0x00, // Dacl
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid group offset",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x00, 0x80, // Control
				0x00, 0x00, 0x00, 0x00, // Owner
				0xFF, 0xFF, 0xFF, 0xFF, // Group (invalid offset)
				0x00, 0x00, 0x00, 0x00, // Sacl
				0x00, 0x00, 0x00, 0x00, // Dacl
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid SACL offset",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x10, 0x80, // Control (SE_SELF_RELATIVE | SE_SACL_PRESENT)
				0x00, 0x00, 0x00, 0x00, // Owner
				0x00, 0x00, 0x00, 0x00, // Group
				0xFF, 0xFF, 0xFF, 0xFF, // Sacl (invalid offset)
				0x00, 0x00, 0x00, 0x00, // Dacl
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid DACL offset",
			data: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x04, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT)
				0x00, 0x00, 0x00, 0x00, // Owner
				0x00, 0x00, 0x00, 0x00, // Group
				0x00, 0x00, 0x00, 0x00, // Sacl
				0xFF, 0xFF, 0xFF, 0xFF, // Dacl (invalid offset)
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sd, err := ParseSecurityDescriptorBinary(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSecurityDescriptorToStruct() error = %v, wantErr %v", err, tt.wantErr)
				}
				if sd != nil {
					t.Errorf("ParseSecurityDescriptorToStruct() = %v, want nil", sd)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSecurityDescriptorToStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if sd == nil {
				t.Errorf("ParseSecurityDescriptorToStruct() = nil, want not nil")
				return
			}

			sdStr := sd.String()

			if sdStr != tt.want {
				t.Errorf("ParseSecurityDescriptor() = %v, want %v", sdStr, tt.want)
			}
		})
	}
}
