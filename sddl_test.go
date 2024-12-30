package sddl

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestACE_Binary(t *testing.T) {
	tests := []struct {
		name    string
		ace     *ACE
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil ACE",
			ace:     nil,
			wantErr: true,
		},
		{
			name: "nil header",
			ace: &ACE{
				Header:     nil,
				AccessMask: 0x1F01FF,
				SID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
			},
			wantErr: true,
		},
		{
			name: "nil SID",
			ace: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: 0,
					AceSize:  20,
				},
				AccessMask: 0x1F01FF,
				SID:        nil,
			},
			wantErr: true,
		},
		{
			name: "size mismatch",
			ace: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: 0,
					AceSize:  10, // Wrong size (should be 20)
				},
				AccessMask: 0x1F01FF,
				SID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
			},
			wantErr: true,
		},
		{
			name: "valid basic ACE (SYSTEM - Full Access)",
			ace: &ACE{
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
			want: []byte{
				// ACE Header
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags (none)
				0x14, 0x00, // Size (20 bytes)
				// Access Mask
				0xFF, 0x01, 0x1F, 0x00, // 0x1F01FF (Full Access)
				// SID (SYSTEM)
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
			},
			wantErr: false,
		},
		{
			name: "valid audit ACE with flags",
			ace: &ACE{
				Header: &ACEHeader{
					AceType:  SYSTEM_AUDIT_ACE_TYPE,
					AceFlags: SUCCESSFUL_ACCESS_ACE | FAILED_ACCESS_ACE,
					AceSize:  20,
				},
				AccessMask: 0x120089, // File Read
				SID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{18},
				},
			},
			want: []byte{
				// ACE Header
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0xC0,       // Flags (SUCCESSFUL_ACCESS_ACE | FAILED_ACCESS_ACE)
				0x14, 0x00, // Size (20 bytes)
				// Access Mask
				0x89, 0x00, 0x12, 0x00, // 0x120089 (File Read)
				// SID (SYSTEM)
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
			},
			wantErr: false,
		},
		{
			name: "valid ACE with inheritance flags",
			ace: &ACE{
				Header: &ACEHeader{
					AceType:  ACCESS_ALLOWED_ACE_TYPE,
					AceFlags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
					AceSize:  24,
				},
				AccessMask: 0x1F01FF,
				SID: &SID{
					Revision:            1,
					IdentifierAuthority: 5,
					SubAuthority:        []uint32{32, 544}, // BUILTIN\Administrators
				},
			},
			want: []byte{
				// ACE Header
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x03,       // Flags (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
				0x18, 0x00, // Size (24 bytes)
				// Access Mask
				0xFF, 0x01, 0x1F, 0x00, // 0x1F01FF (Full Access)
				// SID (BUILTIN\Administrators)
				0x01,                               // Revision
				0x02,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority
				0x20, 0x00, 0x00, 0x00, // SubAuthority[0] (32)
				0x20, 0x02, 0x00, 0x00, // SubAuthority[1] (544)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ace.Binary()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ACE.Binary() error = nil, wantErr = true")
				}
				return
			}

			if err != nil {
				t.Errorf("ACE.Binary() unexpected error = %v", err)
				return
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("ACE.Binary() = %v, want %v", got, tt.want)

				// Print detailed comparison for debugging
				if len(got) != len(tt.want) {
					t.Errorf("Length mismatch: got %d bytes, want %d bytes", len(got), len(tt.want))
				} else {
					for i := range got {
						if got[i] != tt.want[i] {
							t.Errorf("Mismatch at byte %d: got 0x%02X, want 0x%02X", i, got[i], tt.want[i])
						}
					}
				}
			}

			// Check reversibility for both binary and string
			back, err := parseACEBinary(got)
			if err != nil {
				t.Errorf("Binary() -> parseACEBinary() error parsing back binary representation: %v", err)
				return
			}
			compareACEs(t, "Binary() -> parseACEBinary()", back, tt.ace)

			str, err := tt.ace.String()
			if err != nil {
				t.Errorf("Binary() -> ACE.String() unexpected error = %v", err)
				return
			}
			back, err = parseACEString(str)
			if err != nil {
				t.Errorf("Binary() -> ACE.String() -> parseACEString() error parsing back string representation: %v", err)
				return
			}
			compareACEs(t, "Binary() -> ACE.String() -> parseACEString()", back, tt.ace)
		})
	}
}

func TestACL_Binary(t *testing.T) {
	t.Parallel()

	// formatBytes is a helper function to format byte slices for better error messages
	var formatBytes = func(b []byte) string {
		if b == nil {
			return "nil"
		}
		var builder strings.Builder
		for i, by := range b {
			if i > 0 {
				if i%16 == 0 {
					builder.WriteString("\n")
				} else {
					builder.WriteString(" ")
				}
			}
			builder.WriteString(fmt.Sprintf("%02x", by))
		}
		return builder.String()
	}

	tests := []struct {
		name    string
		acl     *ACL
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil ACL",
			acl:     nil,
			want:    nil,
			wantErr: true,
		},
		{
			name: "Empty ACL",
			acl: &ACL{
				AclRevision: 2,
				Sbzl:        0,
				AclSize:     8, // Just header size
				AceCount:    0,
				Sbz2:        0,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
			},
			want: []byte{
				0x02,       // Revision
				0x00,       // Sbz1
				0x08, 0x00, // Size (8 bytes)
				0x00, 0x00, // AceCount (0)
				0x00, 0x00, // Sbz2
			},
			wantErr: false,
		},
		{
			name: "ACL with single ACE - Allow System Full Access",
			acl: &ACL{
				AclRevision: 2,
				Sbzl:        0,
				AclSize:     28, // 8 (header) + 20 (ACE)
				AceCount:    1,
				Sbz2:        0,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF, // Full Access
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,            // NT Authority
							SubAuthority:        []uint32{18}, // Local System
						},
					},
				},
			},
			want: []byte{
				// ACL Header
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes)
				0x01, 0x00, // AceCount (1)
				0x00, 0x00, // Sbz2
				// ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				// SID (S-1-5-18, SYSTEM)
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (NT)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
			},
			wantErr: false,
		},
		{
			name: "ACL with multiple ACEs",
			acl: &ACL{
				AclRevision: 2,
				Sbzl:        0,
				AclSize:     48, // 8 (header) + 20 (first ACE) + 20 (second ACE)
				AceCount:    2,
				Sbz2:        0,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
				ACEs: []ACE{
					{
						Header: &ACEHeader{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x1F01FF, // Full Access
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 5,
							SubAuthority:        []uint32{18}, // System
						},
					},
					{
						Header: &ACEHeader{
							AceType:  ACCESS_DENIED_ACE_TYPE,
							AceFlags: 0,
							AceSize:  20,
						},
						AccessMask: 0x120089, // Read Access
						SID: &SID{
							Revision:            1,
							IdentifierAuthority: 1,
							SubAuthority:        []uint32{0}, // Everyone
						},
					},
				},
			},
			want: []byte{
				// ACL Header
				0x02,       // Revision
				0x00,       // Sbz1
				0x30, 0x00, // Size (48 bytes)
				0x02, 0x00, // AceCount (2)
				0x00, 0x00, // Sbz2
				// First ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (NT)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
				// Second ACE
				0x01,       // Type (ACCESS_DENIED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size (20 bytes)
				0x89, 0x00, 0x12, 0x00, // Access mask (Read Access)
				0x01,                               // Revision
				0x01,                               // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority (World)
				0x00, 0x00, 0x00, 0x00, // SubAuthority (0)
			},
			wantErr: false,
		},
		{
			name: "ACL size mismatch",
			acl: &ACL{
				AclRevision: 2,
				Sbzl:        0,
				AclSize:     10, // Incorrect size
				AceCount:    1,
				Sbz2:        0,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
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
			want:    nil,
			wantErr: true,
		},
		{
			name: "ACE count mismatch",
			acl: &ACL{
				AclRevision: 2,
				Sbzl:        0,
				AclSize:     28,
				AceCount:    2, // Incorrect count
				Sbz2:        0,
				AclType:     "D",
				Control:     SE_DACL_PRESENT,
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
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.acl.Binary()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ACL.Binary() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("ACL.Binary() =\n%v\nwant\n%v", formatBytes(got), formatBytes(tt.want))
			}

			// Check reversibility for both binary and string
			back, err := parseACLBinary(got, tt.acl.AclType, tt.acl.Control)
			if err != nil {
				t.Errorf("ACL.Binary() -> parseACLBinary() got error: %v", err)
				return
			}
			compareACLs(t, "ACL.Binary() -> parseACLBinary()", back, tt.acl)

			str, err := tt.acl.String()
			if err != nil {
				t.Errorf("ACL.Binary() -> ACL.String() got error: %v", err)
				return
			}
			back, err = parseACLString(str)
			if err != nil {
				t.Errorf("ACL.Binary() -> ACL.String() -> parseACLString() got error: %v", err)
				return
			}
			compareACLs(t, "ACL.Binary() -> ACL.String() -> parseACLString()", back, tt.acl)
		})
	}
}

func TestSecurityDescriptor_Binary(t *testing.T) {
	t.Parallel()

	// Helper function to create a basic SID
	createSID := func(authority uint64, subAuth ...uint32) *SID {
		return &SID{
			Revision:            1,
			IdentifierAuthority: authority,
			SubAuthority:        subAuth,
		}
	}

	// Helper function to create a basic ACE
	createACE := func(aceType byte, aceFlags byte, accessMask uint32, sid *SID) *ACE {
		size := uint16(8 + 12) // 8 bytes for header+mask + minimum 12 bytes for SID
		if sid != nil {
			size = uint16(8 + 8 + 4*len(sid.SubAuthority))
		}
		return &ACE{
			Header: &ACEHeader{
				AceType:  aceType,
				AceFlags: aceFlags,
				AceSize:  size,
			},
			AccessMask: accessMask,
			SID:        sid,
		}
	}

	// Helper function to create a basic ACL
	createACL := func(aclType string, control uint16, aces ...ACE) *ACL {
		size := uint16(8) // ACL header size
		for _, ace := range aces {
			size += ace.Header.AceSize
		}
		return &ACL{
			AclRevision: 2,
			Sbzl:        0,
			AclSize:     size,
			AceCount:    uint16(len(aces)),
			Sbz2:        0,
			AclType:     aclType,
			Control:     control,
			ACEs:        aces,
		}
	}

	tests := []struct {
		name    string
		sd      *SecurityDescriptor
		want    []byte
		wantErr bool
	}{
		{
			name:    "Nil security descriptor",
			sd:      nil,
			wantErr: true,
		},

		{
			name: "Empty self-relative security descriptor",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
			},
			want: []byte{
				0x01,       // Revision
				0x00,       // Sbz1
				0x2b, 0x80, // Control (SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED)
				0x00, 0x00, 0x00, 0x00, // Owner offset
				0x00, 0x00, 0x00, 0x00, // Group offset
				0x00, 0x00, 0x00, 0x00, // Sacl offset
				0x00, 0x00, 0x00, 0x00, // Dacl offset
			},
		},

		{
			name: "Security descriptor with owner only (SYSTEM)",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
				OwnerSID: createSID(5, 18), // SYSTEM
			},
			want: []byte{
				// Header
				0x01,       // Revision
				0x00,       // Sbz1
				0x2a, 0x80, // Control (SE_SELF_RELATIVE | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED)
				0x14, 0x00, 0x00, 0x00, // Owner offset (20)
				0x00, 0x00, 0x00, 0x00, // Group offset
				0x00, 0x00, 0x00, 0x00, // Sacl offset
				0x00, 0x00, 0x00, 0x00, // Dacl offset
				// Owner SID (SYSTEM - S-1-5-18)
				0x01, 0x01, // Revision, SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (5)
				0x12, 0x00, 0x00, 0x00, // SubAuthority (18)
			},
		},

		{
			name: "Security descriptor with owner and group",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED,
				OwnerSID: createSID(5, 18), // SYSTEM
				GroupSID: createSID(1, 0),  // Everyone
			},
			want: []byte{
				// Header
				0x01,       // Revision
				0x00,       // Sbz1
				0x28, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED)
				0x14, 0x00, 0x00, 0x00, // Owner offset (20)
				0x20, 0x00, 0x00, 0x00, // Group offset (32)
				0x00, 0x00, 0x00, 0x00, // Sacl offset
				0x00, 0x00, 0x00, 0x00, // Dacl offset
				// Owner SID (SYSTEM)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
				// Group SID (Everyone)
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
			},
		},

		{
			name: "Security descriptor with DACL",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT | SE_SACL_DEFAULTED,
				DACL: createACL("D", SE_SELF_RELATIVE|SE_OWNER_DEFAULTED|SE_GROUP_DEFAULTED|SE_DACL_PRESENT|SE_SACL_DEFAULTED, // Same as SD.Control since this field is a copy
					*createACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, createSID(5, 18))), // Full access for SYSTEM
			},
			want: []byte{
				// Header
				0x01,       // Revision
				0x00,       // Sbz1
				0x27, 0x80, // Control (SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT | SE_SACL_DEFAULTED)
				0x00, 0x00, 0x00, 0x00, // Owner offset
				0x00, 0x00, 0x00, 0x00, // Group offset
				0x00, 0x00, 0x00, 0x00, // Sacl offset
				0x14, 0x00, 0x00, 0x00, // Dacl offset (20)
				// DACL
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
				0x01, 0x01, // SID: Rev=1, Count=1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority=5
				0x12, 0x00, 0x00, 0x00, // SubAuth=18 (SYSTEM)
			},
		},

		{
			name: "Security descriptor with SACL",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SELF_RELATIVE | SE_SACL_PRESENT,
				SACL: createACL("S", SE_OWNER_DEFAULTED|SE_GROUP_DEFAULTED|SE_DACL_DEFAULTED|SE_SELF_RELATIVE|SE_SACL_PRESENT, // Same as SD.Control since this field is a copy
					*createACE(SYSTEM_AUDIT_ACE_TYPE, SUCCESSFUL_ACCESS_ACE, 0x1F01FF, createSID(5, 18))), // Audit SYSTEM access
			},
			want: []byte{
				// Header
				0x01,       // Revision
				0x00,       // Sbz1
				0x1b, 0x80, // Control (SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SELF_RELATIVE | SE_SACL_PRESENT)
				0x00, 0x00, 0x00, 0x00, // Owner offset
				0x00, 0x00, 0x00, 0x00, // Group offset
				0x14, 0x00, 0x00, 0x00, // Sacl offset (20)
				0x00, 0x00, 0x00, 0x00, // Dacl offset
				// SACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes = 8 header + 20 ACE)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// ACE
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x40,       // Flags (SUCCESSFUL_ACCESS_ACE)
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask (Full Access)
				0x01, 0x01, // SID: Rev=1, Count=1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority=5
				0x12, 0x00, 0x00, 0x00, // SubAuth=18 (SYSTEM)
			},
		},

		{
			name: "Complete security descriptor",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
				OwnerSID: createSID(5, 18), // SYSTEM
				GroupSID: createSID(1, 0),  // Everyone
				SACL: createACL("S", SE_SELF_RELATIVE|SE_DACL_PRESENT|SE_SACL_PRESENT, // Same as SD.Control since this field is a copy
					*createACE(SYSTEM_AUDIT_ACE_TYPE, SUCCESSFUL_ACCESS_ACE, 0x1F01FF, createSID(5, 18))),
				DACL: createACL("D", SE_SELF_RELATIVE|SE_DACL_PRESENT|SE_SACL_PRESENT, // Same as SD.Control since this field is a copy
					*createACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, createSID(5, 18))),
			},
			want: []byte{
				// Header
				0x01,       // Revision
				0x00,       // Sbz1
				0x14, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT)
				0x14, 0x00, 0x00, 0x00, // Owner offset (20)
				0x20, 0x00, 0x00, 0x00, // Group offset (32)
				0x2C, 0x00, 0x00, 0x00, // Sacl offset (44)
				0x48, 0x00, 0x00, 0x00, // Dacl offset (72)
				// Owner SID (SYSTEM)
				0x01, 0x01, // Rev=1, Count=1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority=5
				0x12, 0x00, 0x00, 0x00, // SubAuth=18
				// Group SID (Everyone)
				0x01, 0x01, // Rev=1, Count=1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Authority=1
				0x00, 0x00, 0x00, 0x00, // SubAuth=0
				// SACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// SACL ACE
				0x02,       // Type (SYSTEM_AUDIT_ACE_TYPE)
				0x40,       // Flags (SUCCESSFUL_ACCESS_ACE)
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
				// DACL
				0x02,       // Revision
				0x00,       // Sbz1
				0x1C, 0x00, // Size (28 bytes)
				0x01, 0x00, // AceCount
				0x00, 0x00, // Sbz2
				// DACL ACE
				0x00,       // Type (ACCESS_ALLOWED_ACE_TYPE)
				0x00,       // Flags
				0x14, 0x00, // Size (20 bytes)
				0xFF, 0x01, 0x1F, 0x00, // Access mask
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00,
			},
		},

		// errors

		{
			name: "Error: SACL present but flag not set",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE,
				SACL:     createACL("S", 0),
			},
			wantErr: true,
		},

		{
			name: "Error: DACL present but flag not set",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE,
				DACL:     createACL("D", 0),
			},
			wantErr: true,
		},

		{
			name: "Error: SACL flag set but SACL nil",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_SACL_PRESENT,
			},
			wantErr: true,
		},

		{
			name: "Error: DACL flag set but DACL nil",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE | SE_DACL_PRESENT,
			},
			wantErr: true,
		},

		{
			name: "Error: Invalid Owner SID",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE,
				OwnerSID: &SID{Revision: 2}, // Invalid revision
			},
			wantErr: true,
		},

		{
			name: "Error: Invalid Group SID",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SE_SELF_RELATIVE,
				GroupSID: &SID{Revision: 2}, // Invalid revision
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.sd.Binary()
			if tt.wantErr {
				if err == nil {
					t.Error("Binary() error = nil, wantErr = true")
				}
				return
			}

			if err != nil {
				t.Errorf("Binary() unexpected error = %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("Binary() length mismatch\ngot  = %d bytes\nwant = %d bytes", len(got), len(tt.want))
				return
			}

			// Find first difference in binary output
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Binary() mismatch at offset %d (0x%02x):\ngot  = %02x\nwant = %02x",
						i, i, got[i], tt.want[i])

					// Print context around the mismatch
					start := i - 4
					if start < 0 {
						start = 0
					}
					end := i + 4
					if end > len(got) {
						end = len(got)
					}

					t.Errorf("Context around mismatch (offset 0x%02x):", i)
					t.Errorf("got  = % 02x", got[start:end])
					t.Errorf("want = % 02x", tt.want[start:end])
					return
				}
			}

			// If we get here, the lengths match and all bytes match

			// Check reversibility for both binary and string
			back, err := ParseSecurityDescriptorBinary(got)
			if err != nil {
				t.Errorf("Binary() -> ParseSecurityDescriptorBinary() unexpected error = %v", err)
				return
			}
			compareSecurityDescriptors(t, back, tt.sd)

			str, err := tt.sd.String()
			if err != nil {
				t.Errorf("String() unexpected error = %v", err)
				return
			}

			sd, err := ParseSecurityDescriptorString(str)
			if err != nil {
				t.Errorf("String() -> ParseSecurityDescriptorString() unexpected error = %v", err)
				return
			}
			compareSecurityDescriptors(t, sd, tt.sd)
		})
	}
}

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

			// Check reversibility for both binary and string
			back, err := parseSIDBinary(got)
			if err != nil {
				t.Errorf("Binary() -> parseSIDBinary() error parsing back binary representation: %v", err)
				return
			}
			compareSIDs(t, "Binary() -> parseSIDBinary()", back, tt.sid)

			str, err := tt.sid.String()
			if err != nil {
				t.Errorf("Binary() -> String() error: %v", err)
				return
			}
			back, err = parseSIDString(str)
			if err != nil {
				t.Errorf("Binary() -> String() -> parseSIDString() error parsing back string representation: %v", err)
				return
			}
			compareSIDs(t, "Binary() -> String() -> parseSIDString()", back, tt.sid)
		})
	}
}
