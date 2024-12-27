package sddl

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

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

func TestParseACLString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      *ACL
		wantErr   bool
		errString string
	}{
		{
			name:      "Empty string",
			input:     "",
			wantErr:   true,
			errString: "empty ACL string",
		},
		{
			name:      "Invalid format - no colon",
			input:     "D(A;;FA;;;SY)",
			wantErr:   true,
			errString: "invalid ACL string format: must start with 'D:' or 'S:'",
		},
		{
			name:      "Invalid ACL type",
			input:     "X:(A;;FA;;;SY)",
			wantErr:   true,
			errString: "invalid ACL type: must start with 'D:' or 'S:'",
		},
		{
			name:  "Empty DACL",
			input: "D:",
			want: &ACL{
				AclRevision: 2,
				AclSize:     8,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
			},
		},
		{
			name:  "Empty SACL",
			input: "S:",
			want: &ACL{
				AclRevision: 2,
				AclSize:     8,
				AclType:     "S",
				Control:     SE_SACL_PRESENT,
			},
		},
		{
			name:  "Basic DACL with single ACE",
			input: "D:(A;;FA;;;SY)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     28, // 8 (header) + 20 (ACE size)
				AceCount:    1,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF, // FA - Full Access
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18}, // SYSTEM
						},
					},
				},
			},
		},
		{
			name:  "DACL with multiple ACEs",
			input: "D:(A;;FA;;;SY)(D;;FR;;;WD)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     48, // 8 (header) + 20 (first ACE) + 20 (second ACE)
				AceCount:    2,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF, // FA
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18}, // SYSTEM
						},
					},
					{
						Header: &ACEHeader{
							AceType:  ACCESS_DENIED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x120089, // FR
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 1,
							SubAuthority:        []uint32{0}, // Everyone
						},
					},
				},
			},
		},
		{
			name:  "SACL with audit ACE",
			input: "S:(AU;SA;FA;;;SY)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     28,
				AceCount:    1,
				AclType:     "S",
				Control:     SE_SACL_PRESENT,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  SYSTEM_AUDIT_ACE_TYPE,
							AceFlags: SUCCESSFUL_ACCESS_ACE,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF,
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18},
						},
					},
				},
			},
		},
		{
			name:  "DACL with protected flag",
			input: "D:P(A;;FA;;;SY)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     28,
				AceCount:    1,
				AclType:     "D",
				Control:     SE_DACL_PRESENT | SE_DACL_PROTECTED,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF,
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18},
						},
					},
				},
			},
		},
		{
			name:  "DACL with auto-inherited flag",
			input: "D:AI(A;;FA;;;SY)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     28,
				AceCount:    1,
				AclType:     "D",
				Control:     SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF,
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18},
						},
					},
				},
			},
		},
		{
			name:  "SACL with multiple flags",
			input: "S:PAI(AU;SA;FA;;;SY)",
			want: &ACL{
				AclRevision: 2,
				AclSize:     28,
				AceCount:    1,
				AclType:     "S",
				Control:     SE_SACL_PRESENT | SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  SYSTEM_AUDIT_ACE_TYPE,
							AceFlags: SUCCESSFUL_ACCESS_ACE,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF,
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18},
						},
					},
				},
			},
		},
		{
			name:      "Invalid ACE format",
			input:     "D:A;;FA;;;SY)", // Missing opening parenthesis
			wantErr:   true,
			errString: "invalid ACL format: missing opening parenthesis",
		},
		{
			name:      "Missing closing parenthesis",
			input:     "D:(A;;FA;;;SY",
			wantErr:   true,
			errString: "invalid ACE format: missing closing parenthesis",
		},
		{
			name:  "Empty DACL with flags",
			input: "D:PAI",
			want: &ACL{
				AclRevision: 2,
				AclSize:     8,
				AclType:     "D",
				Control:     SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
			},
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable for parallel testing
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseACLString(tt.input)

			// Check error cases
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseACLFromString() error= nil, wantErr = true")
					return /*  */
				}
				if tt.errString != "" && err.Error() != tt.errString {
					t.Errorf("parseACLFromString() error = %v, wantErr = %v", err, tt.errString)
				}
				return
			}

			// Check non-error cases
			if err != nil {
				t.Errorf("parseACLFromString() unexpected error = %v", err)
				return
			}

			if got == nil {
				t.Fatal("parseACLFromString() = nil, want non-nil")
			}

			// Compare ACL fields
			if got.AclRevision != tt.want.AclRevision {
				t.Errorf("AclRevision = %v, want %v", got.AclRevision, tt.want.AclRevision)
			}
			if got.AclSize != tt.want.AclSize {
				t.Errorf("AclSize = %v, want %v", got.AclSize, tt.want.AclSize)
			}
			if got.AceCount != tt.want.AceCount {
				t.Errorf("AceCount = %v, want %v", got.AceCount, tt.want.AceCount)
			}
			if got.AclType != tt.want.AclType {
				t.Errorf("AclType = %v, want %v", got.AclType, tt.want.AclType)
			}
			if got.Control != tt.want.Control {
				t.Errorf("Control = %v, want %v", got.Control, tt.want.Control)
			}

			// Compare ACEs
			if len(got.ACEs) != len(tt.want.ACEs) {
				t.Errorf("len(ACEs) = %v, want %v", len(got.ACEs), len(tt.want.ACEs))
				return
			}

			for i := range got.ACEs {
				// Compare ACE Header
				if got.ACEs[i].Header.AceType != tt.want.ACEs[i].Header.AceType {
					t.Errorf("ACE[%d].Header.AceType = %v, want %v",
						i, got.ACEs[i].Header.AceType, tt.want.ACEs[i].Header.AceType)
				}
				if got.ACEs[i].Header.AceFlags != tt.want.ACEs[i].Header.AceFlags {
					t.Errorf("ACE[%d].Header.AceFlags = %v, want %v",
						i, got.ACEs[i].Header.AceFlags, tt.want.ACEs[i].Header.AceFlags)
				}
				if got.ACEs[i].Header.AceSize != tt.want.ACEs[i].Header.AceSize {
					t.Errorf("ACE[%d].Header.AceSize = %v, want %v",
						i, got.ACEs[i].Header.AceSize, tt.want.ACEs[i].Header.AceSize)
				}

				// Compare ACE AccessMask
				if got.ACEs[i].AccessMask != tt.want.ACEs[i].AccessMask {
					t.Errorf("ACE[%d].AccessMask = %v, want %v",
						i, got.ACEs[i].AccessMask, tt.want.ACEs[i].AccessMask)
				}

				// Compare ACE SID
				if !reflect.DeepEqual(got.ACEs[i].SID, tt.want.ACEs[i].SID) {
					t.Errorf("ACE[%d].SID = %v, want %v",
						i, got.ACEs[i].SID, tt.want.ACEs[i].SID)
				}
			}
		})
	}
}

func TestParseSecurityDescriptorString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    *SecurityDescriptor
		wantErr bool
	}{
		{
			name:  "Empty string",
			input: "",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
			},
			wantErr: false,
		},

		{
			name:  "Owner only",
			input: "O:SY",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
				OwnerSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
			},
			wantErr: false,
		},

		{
			name:  "Group only",
			input: "G:BA",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
				GroupSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{32, 544},
				},
			},
			wantErr: false,
		},

		{
			name:  "Owner and Group only",
			input: "O:SYG:BA",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
				OwnerSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
				GroupSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{32, 544},
				},
			},
			wantErr: false,
		},

		{
			name:  "Only Empty DACL",
			input: "D:",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_SACL_DEFAULTED | SE_DACL_PRESENT,
				DACL: &ACL{
					AclRevision: 2,
					AclSize:     8,
					AclType:     "D",
					Control:     SE_DACL_PRESENT,
				},
			},
			wantErr: false,
		},

		{
			name:  "Only Empty SACL",
			input: "S:",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_PRESENT,
				SACL: &ACL{
					AclRevision: 2,
					AclSize:     8,
					AclType:     "S",
					Control:     SE_SACL_PRESENT,
				},
			},
			wantErr: false,
		},

		{
			name:  "Protected DACL",
			input: "D:P(A;;FA;;;SY)",
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_SACL_DEFAULTED | SE_DACL_PRESENT | SE_DACL_PROTECTED,
				DACL: &ACL{
					AclRevision: 2,
					AclSize:     28,
					AceCount:    1,
					AclType:     "D",
					Control:     SE_DACL_PRESENT | SE_DACL_PROTECTED,
					ACEs: []ACE{
						{
							Header: &ACEHeader{
								AceType:  ACCESS_ALLOWED_ACE_TYPE,
								AceFlags: 0,
								AceSize:  20,
							},
							AccessMask: 0x1F01FF,
							SID: &SID{
								Revision:            1,
								IdentifierAuthority: 5,
								SubAuthority:        []uint32{18},
							},
						},
					},
				},
			},
			wantErr: false,
		},

		{
			name:  "Complete security descriptor",
			input: "O:SYG:BAD:PAI(A;;FA;;;SY)(D;;FR;;;WD)S:AI(AU;SA;FA;;;BA)",
			want: &SecurityDescriptor{
				Revision: 1,
				Control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT |
					SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_AUTO_INHERITED,
				OwnerSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
				GroupSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{32, 544},
				},
				DACL: &ACL{
					AclRevision: 2,
					AclSize:     48, // 4 bytes for AceCount and Sbz1, 40 bytes for the two ACEs, 4 bytes for Sbz2
					AceCount:    2,
					AclType:     "D",
					Control:     SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED,
					ACEs: []ACE{
						{
							Header: &ACEHeader{
								AceType:  ACCESS_ALLOWED_ACE_TYPE,
								AceFlags: 0,
								AceSize:  20, // 4 bytes for ACE header + 4 bytes for mask + 12 bytes for SID
							},
							AccessMask: 0x1F01FF,
							SID: &SID{
								Revision:            1,
								IdentifierAuthority: 5,
								SubAuthority:        []uint32{18},
							},
						},
						{
							Header: &ACEHeader{
								AceType:  ACCESS_DENIED_ACE_TYPE,
								AceFlags: 0,
								AceSize:  20, // 4 bytes for ACE header + 4 bytes for mask + 12 bytes for SID
							},
							AccessMask: 0x120089,
							SID: &SID{
								Revision:            1,
								IdentifierAuthority: 1,
								SubAuthority:        []uint32{0},
							},
						},
					},
				},
				SACL: &ACL{
					AclRevision: 2,
					AclSize:     32, // 4 bytes for AceCount and Sbz1, 24 bytes for the single ACE, 4 bytes for Sbz2
					AceCount:    1,
					AclType:     "S",
					Control:     SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED,
					ACEs: []ACE{
						{
							Header: &ACEHeader{
								AceType:  SYSTEM_AUDIT_ACE_TYPE,
								AceFlags: SUCCESSFUL_ACCESS_ACE,
								AceSize:  24, // 4 bytes for ACE header, 4 bytes for access mask, 8 bytes for SID header, 4 bytes for 1 sub-authority
							},
							AccessMask: 0x1F01FF,
							SID: &SID{
								Revision:            1,
								IdentifierAuthority: 5,
								SubAuthority:        []uint32{32, 544},
							},
						},
					},
				},
			},
			wantErr: false,
		},

		{
			name:    "Invalid format - no separator",
			input:   "O-SY",
			wantErr: true,
		},

		{
			name:    "Invalid SID format",
			input:   "O:INVALID",
			wantErr: true,
		},

		{
			name:    "Invalid DACL format",
			input:   "D:X",
			wantErr: true,
		},

		{
			name:    "Invalid ACE format",
			input:   "D:(A;FR;;;SY", // Missing closing parenthesis
			wantErr: true,
		},

		{
			name:    "Non-standard order of components",
			input:   "D:(A;;FA;;;SY)O:SY",
			wantErr: false,
			want: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_GROUP_DEFAULTED | SE_SACL_DEFAULTED | SE_DACL_PRESENT,
				DACL: &ACL{
					AclRevision: 2,
					AclSize:     28, // 4 bytes for AceCount and Sbz1, 20 bytes for the single ACE, 4 bytes for Sbz2
					AceCount:    1,
					AclType:     "D",
					Control:     SE_DACL_PRESENT,
					ACEs: []ACE{
						{
							Header: &ACEHeader{
								AceType:  ACCESS_ALLOWED_ACE_TYPE,
								AceFlags: 0,
								AceSize:  20, // 4 bytes for ACE header + 4 bytes for mask + 12 bytes for SID
							},
							AccessMask: 0x1F01FF,
							SID: &SID{
								Revision:            1,
								IdentifierAuthority: 5,
								SubAuthority:        []uint32{18},
							},
						},
					},
				},
				OwnerSID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
			},
		},

		{
			name:  "All control flags",
			input: "D:PAIARRNOIOS:PAIARRNOIO",
			want: &SecurityDescriptor{
				Revision: 1,
				Control: SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED |
					SE_DACL_PRESENT | SE_SACL_PRESENT |
					SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_RE |
					SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_AUTO_INHERIT_RE,
				DACL: &ACL{
					AclRevision: 2,
					AclSize:     8,
					AclType:     "D",
					Control: SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED |
						SE_DACL_AUTO_INHERIT_RE | SE_DACL_DEFAULTED,
				},
				SACL: &ACL{
					AclRevision: 2,
					AclSize:     8,
					AclType:     "S",
					Control: SE_SACL_PRESENT | SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED |
						SE_SACL_AUTO_INHERIT_RE | SE_SACL_DEFAULTED,
				},
			},
			wantErr: false,
		},

		// {
		// 	name:  "Non-standard order of components",
		// 	input: "G:SYD:(A;;FA;;;BA)O:BA",
		// 	want: &SecurityDescriptor{
		// 		Revision: 1,
		// 		Control:  SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_DEFAULTED,
		// 		GroupSID: &SID{
		// 			Revision:            1,
		// 			IdentifierAuthority: 5,
		// 			SubAuthority:        []uint32{18},
		// 		},
		// 		OwnerSID: &SID{
		// 			Revision:            1,
		// 			IdentifierAuthority: 5,
		// 			SubAuthority:        []uint32{32, 544},
		// 		},
		// 		DACL: &ACL{
		// 			AclRevision: 2,
		// 			AclSize:     28,
		// 			AceCount:    1,
		// 			AclType:     "D",
		// 			Control:     SE_DACL_PRESENT,
		// 			ACEs: []ACE{
		// 				{
		// 					Header: &ACEHeader{
		// 						AceType:  ACCESS_ALLOWED_ACE_TYPE,
		// 						AceFlags: 0,
		// 						AceSize:  24,
		// 					},
		// 					AccessMask: 0x1F01FF,
		// 					SID: &SID{
		// 						Revision:            1,
		// 						IdentifierAuthority: 5,
		// 						SubAuthority:        []uint32{32, 544},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	wantErr: false,
		// },
	}

	for _, tt := range tests {
		tt := tt // Capture range variable for parallel testing
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSecurityDescriptorString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSecurityDescriptorString() error = nil, wantErr = true")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSecurityDescriptorString() unexpected error = %v", err)
				return
			}

			// Compare SecurityDescriptor fields
			compareSecurityDescriptors(t, got, tt.want)
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

// Helper function to compare ACL fields
func compareACLs(t *testing.T, prefix string, got, want *ACL) {
	t.Helper()

	if got.AclRevision != want.AclRevision {
		t.Errorf("%s.AclRevision = %v, want %v", prefix, got.AclRevision, want.AclRevision)
	}

	if got.AclSize != want.AclSize {
		t.Errorf("%s.AclSize = %v, want %v", prefix, got.AclSize, want.AclSize)
	}

	if got.AceCount != want.AceCount {
		t.Errorf("%s.AceCount = %v, want %v", prefix, got.AceCount, want.AceCount)
	}

	if got.AclType != want.AclType {
		t.Errorf("%s.AclType = %v, want %v", prefix, got.AclType, want.AclType)
	}

	if got.Control != want.Control {
		t.Errorf("%s.Control = %v, want %v", prefix, got.Control, want.Control)
	}

	if len(got.ACEs) != len(want.ACEs) {
		t.Errorf("%s.ACEs length = %v, want %v", prefix, len(got.ACEs), len(want.ACEs))
		return
	}

	for i := range got.ACEs {
		compareACEs(t, fmt.Sprintf("%s.ACE[%d]", prefix, i), &got.ACEs[i], &want.ACEs[i])
	}
}

// Helper function to compare ACE fields
func compareACEs(t *testing.T, prefix string, got, want *ACE) {
	t.Helper()

	// Compare ACE Header
	if got.Header.AceType != want.Header.AceType {
		t.Errorf("%s.Header.AceType = %v, want %v", prefix, got.Header.AceType, want.Header.AceType)
	}

	if got.Header.AceFlags != want.Header.AceFlags {
		t.Errorf("%s.Header.AceFlags = %v, want %v", prefix, got.Header.AceFlags, want.Header.AceFlags)
	}

	if got.Header.AceSize != want.Header.AceSize {
		t.Errorf("%s.Header.AceSize = %v, want %v", prefix, got.Header.AceSize, want.Header.AceSize)
	}

	// Compare ACE AccessMask
	if got.AccessMask != want.AccessMask {
		t.Errorf("%s.AccessMask = %v, want %v", prefix, got.AccessMask, want.AccessMask)
	}

	// Compare ACE SID
	if (got.SID == nil) != (want.SID == nil) {
		t.Errorf("%s.SID presence mismatch: got %v, want %v", prefix, got.SID != nil, want.SID != nil)
	} else if got.SID != nil {
		compareSIDs(t, prefix+".SID", got.SID, want.SID)
	}
}

// Helper function to compare control flags with detailed difference reporting
func compareControlFlags(t *testing.T, got, want uint16) {
	t.Helper()

	// If flags match exactly, no need to do detailed comparison
	if got == want {
		return
	}

	// Map of control flags to their string descriptions
	controlFlagNames := map[uint16]string{
		SE_OWNER_DEFAULTED:      "SE_OWNER_DEFAULTED",
		SE_GROUP_DEFAULTED:      "SE_GROUP_DEFAULTED",
		SE_DACL_PRESENT:         "SE_DACL_PRESENT",
		SE_DACL_DEFAULTED:       "SE_DACL_DEFAULTED",
		SE_SACL_PRESENT:         "SE_SACL_PRESENT",
		SE_SACL_DEFAULTED:       "SE_SACL_DEFAULTED",
		SE_DACL_AUTO_INHERIT_RE: "SE_DACL_AUTO_INHERIT_RE",
		SE_SACL_AUTO_INHERIT_RE: "SE_SACL_AUTO_INHERIT_RE",
		SE_DACL_AUTO_INHERITED:  "SE_DACL_AUTO_INHERITED",
		SE_SACL_AUTO_INHERITED:  "SE_SACL_AUTO_INHERITED",
		SE_DACL_PROTECTED:       "SE_DACL_PROTECTED",
		SE_SACL_PROTECTED:       "SE_SACL_PROTECTED",
		SE_SELF_RELATIVE:        "SE_SELF_RELATIVE",
	}

	// Build arrays of flag differences
	var (
		missingFlags []string // Flags that are in 'want' but not in 'got'
		extraFlags   []string // Flags that are in 'got' but not in 'want'
	)

	// Check each known flag
	for flag, flagName := range controlFlagNames {
		hasFlag := got&flag != 0
		wantFlag := want&flag != 0

		if wantFlag && !hasFlag {
			missingFlags = append(missingFlags, flagName)
		} else if hasFlag && !wantFlag {
			extraFlags = append(extraFlags, flagName)
		}
	}

	// Detect any unknown flags
	knownFlags := uint16(0)
	for flag := range controlFlagNames {
		knownFlags |= flag
	}

	unknownGot := got &^ knownFlags
	unknownWant := want &^ knownFlags

	if unknownGot != 0 {
		extraFlags = append(extraFlags, fmt.Sprintf("unknown_flags(0x%04x)", unknownGot))
	}
	if unknownWant != 0 {
		missingFlags = append(missingFlags, fmt.Sprintf("unknown_flags(0x%04x)", unknownWant))
	}

	// Sort the arrays for consistent output
	sort.Strings(missingFlags)
	sort.Strings(extraFlags)

	// Build the error message
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("Control flags mismatch (got=0x%04x, want=0x%04x):\n", got, want))

	if len(missingFlags) > 0 {
		msg.WriteString("  Missing flags:\n")
		for _, flag := range missingFlags {
			msg.WriteString(fmt.Sprintf("    - %s\n", flag))
		}
	}

	if len(extraFlags) > 0 {
		msg.WriteString("  Extra flags:\n")
		for _, flag := range extraFlags {
			msg.WriteString(fmt.Sprintf("    + %s\n", flag))
		}
	}

	t.Error(msg.String())
}

// Helper function to compare SecurityDescriptor fields
func compareSecurityDescriptors(t *testing.T, got, want *SecurityDescriptor) {
	t.Helper()

	if got.Revision != want.Revision {
		t.Errorf("Revision = %v, want %v", got.Revision, want.Revision)
	}

	compareControlFlags(t, got.Control, want.Control)

	// Compare Owner SID
	if (got.OwnerSID == nil) != (want.OwnerSID == nil) {
		t.Errorf("OwnerSID presence mismatch: got %v, want %v", got.OwnerSID != nil, want.OwnerSID != nil)
	} else if got.OwnerSID != nil {
		compareSIDs(t, "OwnerSID", got.OwnerSID, want.OwnerSID)
	}

	// Compare Group SID
	if (got.GroupSID == nil) != (want.GroupSID == nil) {
		t.Errorf("GroupSID presence mismatch: got %v, want %v", got.GroupSID != nil, want.GroupSID != nil)
	} else if got.GroupSID != nil {
		compareSIDs(t, "GroupSID", got.GroupSID, want.GroupSID)
	}

	// Compare DACL
	if (got.DACL == nil) != (want.DACL == nil) {
		t.Errorf("DACL presence mismatch: got %v, want %v", got.DACL != nil, want.DACL != nil)
	} else if got.DACL != nil {
		compareACLs(t, "DACL", got.DACL, want.DACL)
	}

	// Compare SACL
	if (got.SACL == nil) != (want.SACL == nil) {
		t.Errorf("SACL presence mismatch: got %v, want %v", got.SACL != nil, want.SACL != nil)
	} else if got.SACL != nil {
		compareACLs(t, "SACL", got.SACL, want.SACL)
	}
}

// Helper function to compare SID fields
func compareSIDs(t *testing.T, prefix string, got, want *SID) {
	t.Helper()

	if got.Revision != want.Revision {
		t.Errorf("%s.Revision = %v, want %v", prefix, got.Revision, want.Revision)
	}

	if got.IdentifierAuthority != want.IdentifierAuthority {
		t.Errorf("%s.IdentifierAuthority = %v, want %v", prefix, got.IdentifierAuthority, want.IdentifierAuthority)
	}

	if len(got.SubAuthority) != len(want.SubAuthority) {
		t.Errorf("%s.SubAuthority length = %v, want %v", prefix, len(got.SubAuthority), len(want.SubAuthority))
		return
	}

	for i, sub := range got.SubAuthority {
		if sub != want.SubAuthority[i] {
			t.Errorf("%s.SubAuthority[%d] = %v, want %v", prefix, i, sub, want.SubAuthority[i])
		}
	}
}
