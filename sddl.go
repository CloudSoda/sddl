package sddl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// constants for SECURITY_DESCRIPTOR parsing
const (
	// Control flags
	SE_OWNER_DEFAULTED                = 0x0001
	SE_GROUP_DEFAULTED                = 0x0002
	SE_DACL_PRESENT                   = 0x0004
	SE_DACL_DEFAULTED                 = 0x0008
	SE_SACL_PRESENT                   = 0x0010
	SE_SACL_DEFAULTED                 = 0x0020
	SE_DACL_TRUSTED                   = 0x0040
	SE_SERVER_SECURITY                = 0x0080
	SE_DACL_AUTO_INHERIT_RE           = 0x0100
	SE_SACL_AUTO_INHERIT_RE           = 0x0200
	SE_DACL_AUTO_INHERITED            = 0x0400
	SE_SACL_AUTO_INHERITED            = 0x0800
	SE_DACL_PROTECTED                 = 0x1000
	SE_SACL_PROTECTED                 = 0x2000
	SE_RESOURCE_MANAGER_CONTROL_VALID = 0x4000
	SE_SELF_RELATIVE                  = 0x8000

	// ACE types
	ACCESS_ALLOWED_ACE_TYPE        = 0x0
	ACCESS_DENIED_ACE_TYPE         = 0x1
	SYSTEM_AUDIT_ACE_TYPE          = 0x2
	SYSTEM_ALARM_ACE_TYPE          = 0x3
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5

	// ACE flags
	OBJECT_INHERIT_ACE       = 0x01
	CONTAINER_INHERIT_ACE    = 0x02
	NO_PROPAGATE_INHERIT_ACE = 0x04
	INHERIT_ONLY_ACE         = 0x08
	INHERITED_ACE            = 0x10
	SUCCESSFUL_ACCESS_ACE    = 0x40
	FAILED_ACCESS_ACE        = 0x80
)

// Well-known SIDs
var wellKnownSids = map[string]string{
	"S-1-0-0":      "NULL",
	"S-1-1-0":      "WD", // Everyone
	"S-1-2-0":      "LG", // Local GROUP
	"S-1-3-0":      "CC", // CREATOR CREATOR
	"S-1-3-1":      "CO", // CREATOR OWNER
	"S-1-3-2":      "CG", // CREATOR GROUP
	"S-1-3-3":      "OW", // OWNER RIGHTS
	"S-1-5-1":      "DU", // DIALUP
	"S-1-5-2":      "AN", // NETWORK
	"S-1-5-3":      "BT", // BATCH
	"S-1-5-4":      "IU", // INTERACTIVE
	"S-1-5-6":      "SU", // SERVICE
	"S-1-5-7":      "AS", // ANONYMOUS
	"S-1-5-8":      "PS", // PROXY
	"S-1-5-9":      "ED", // ENTERPRISE DOMAIN CONTROLLERS
	"S-1-5-10":     "SS", // SELF
	"S-1-5-11":     "AU", // Authenticated Users
	"S-1-5-12":     "RC", // RESTRICTED CODE
	"S-1-5-18":     "SY", // LOCAL SYSTEM
	"S-1-5-32-544": "BA", // BUILTIN\Administrators
	"S-1-5-32-545": "BU", // BUILTIN\Users
	"S-1-5-32-546": "BG", // BUILTIN\Guests
	"S-1-5-32-547": "PU", // BUILTIN\Power Users
	"S-1-5-32-548": "AO", // BUILTIN\Account Operators
	"S-1-5-32-549": "SO", // BUILTIN\Server Operators
	"S-1-5-32-550": "PO", // BUILTIN\Print Operators
	"S-1-5-32-551": "BO", // BUILTIN\Backup Operators
	"S-1-5-32-552": "RE", // BUILTIN\Replicator
	"S-1-5-32-554": "RU", // BUILTIN\Pre-Windows 2000 Compatible Access
	"S-1-5-32-555": "RD", // BUILTIN\Remote Desktop Users
	"S-1-5-32-556": "NO", // BUILTIN\Network Configuration Operators
	"S-1-5-64-10":  "AA", // Administrator Access
	"S-1-5-64-14":  "RA", // Remote Access
	"S-1-5-64-21":  "OA", // Operation Access
}

// Well-known access rights masks
var wellKnownAccessMasks = map[uint32]string{
	0x1F01FF: "FA",       // Full Access
	0x120089: "FR",       // File Read
	0x120116: "WR",       // File Write
	0x1200A9: "RA",       // Read and Execute Access
	0x1F0000: "GR",       // Generic Read
	0x1F0001: "GW",       // Generic Write
	0x1F0002: "GX",       // Generic Execute
	0x1F0003: "GA",       // Generic All
	0x000116: "DCLCRPCR", // Directory Create/List/Read/Pass through/Child rename/Child delete
}

// SecurityDescriptor represents the Windows SECURITY_DESCRIPTOR structure
type SecurityDescriptor struct {
	Revision    byte   // Revision of the security descriptor format
	Sbzl        byte   // Reserved; must be zero
	Control     uint16 // Control flags
	OwnerOffset uint32 // Offset of owner SID in bytes
	GroupOffset uint32 // Offset of group SID in bytes
	SaclOffset  uint32 // Offset of SACL in bytes
	DaclOffset  uint32 // Offset of DACL in bytes
	// The following fields are not part of original structure but are needed for string representation
	OwnerSID *SID // Owner SID
	GroupSID *SID // Group SID
	SACL     *ACL // System ACL
	DACL     *ACL // Discretionary ACL
}

func (sd *SecurityDescriptor) String() string {
	var parts []string
	if sd.OwnerSID != nil {
		parts = append(parts, fmt.Sprintf("O:%s", sd.OwnerSID.String()))
	}
	if sd.GroupSID != nil {
		parts = append(parts, fmt.Sprintf("G:%s", sd.GroupSID.String()))
	}
	if sd.DACL != nil {
		parts = append(parts, sd.DACL.String())
	}
	if sd.SACL != nil {
		parts = append(parts, sd.SACL.String())
	}
	return strings.Join(parts, "")
}

// ACL represents the windows ACL structure
type ACL struct {
	AclRevision byte   // Revision of the ACL format
	Sbzl        byte   // Reserved; must be zero
	AclSize     uint16 // Size of the ACL in bytes
	AceCount    uint16 // Number of ACEs in the ACL
	Sbz2        uint16 // Reserved; must be zero
	// the following two fields are not part of original structure but are needed for string representation
	AclType string // "D" for DACL, "S" for SACL
	Control uint16 // Control flags
	// the following field is not part of original structure but is needed for string representation
	ACEs []ACE // List of ACEs
}

func (a *ACL) String() string {
	var aclFlags []string
	if a.AclType == "D" {
		if a.Control&SE_DACL_PROTECTED != 0 {
			aclFlags = append(aclFlags, "P")
		}
		if a.Control&SE_DACL_AUTO_INHERITED != 0 {
			aclFlags = append(aclFlags, "AI")
		}
	} else if a.AclType == "S" {
		if a.Control&SE_SACL_AUTO_INHERITED != 0 {
			aclFlags = append(aclFlags, "AI")
		}
	}

	var aces []string
	for _, ace := range a.ACEs {
		aces = append(aces, ace.String())
	}

	var result string
	if len(aclFlags) > 0 {
		result = fmt.Sprintf("%s:%s", a.AclType, strings.Join(aclFlags, ""))
	} else {
		result = fmt.Sprintf("%s:", a.AclType)
	}

	return result + strings.Join(aces, "")
}

// ACEHeader represents the Windows ACE_HEADER structure
type ACEHeader struct {
	AceType  byte   // ACE type (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, etc.)
	AceFlags byte   // ACE flags (OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, etc.)
	AceSize  uint16 // Total size of the ACE in bytes
}

// SID represents a Windows Security Identifier (SID)
// Note: SubAuthorityCount  is needed for parsing, but once the structure is built, it can be determined from SubAuthority
type SID struct {
	// Revision indicates the revision level of the SID structure.
	// It is used to determine the format of the SID structure.
	// The current revision level is 1.
	Revision byte
	// IdentifierAuthority is the authority part of the SID. It is a 6-byte
	// value that identifies the authority issuing the SID. The high-order
	// 2 bytes contain the revision level of the SID. The next byte is the
	// identifier authority value. The low-order 3 bytes are zero.
	IdentifierAuthority uint64
	// SubAuthority is the sub-authority parts of the SID.
	// The number of sub-authorities is determined by SubAuthorityCount.
	// The sub-authorities are in the order they appear in the SID string
	// (i.e. S-1-5-21-a-b-c-d-e, where d and e are sub-authorities).
	// The sub-authorities are stored in little-endian order.
	// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
	SubAuthority []uint32
}

// String returns a string representation of the SID. If it corresponds to a well-known SID, it will be translated
// to its short form (e.g. for BUILTIN\Administrators, it will return "BA" instead of "S-1-5-32-544").
func (s *SID) String() string {
	if s == nil || s.Revision == 0 {
		return "NULL"
	}

	authority := fmt.Sprintf("%d", s.IdentifierAuthority)
	if s.IdentifierAuthority >= 1<<32 {
		authority = fmt.Sprintf("0x%x", s.IdentifierAuthority)
	}

	sidStr := fmt.Sprintf("S-%d-%s", s.Revision, authority)
	for _, subAuthority := range s.SubAuthority {
		sidStr += fmt.Sprintf("-%d", subAuthority)
	}

	if wk, ok := wellKnownSids[sidStr]; ok {
		return wk
	}

	return sidStr
}

// ACE represents a Windows Access Control Entry (ACE)
// The ACE structure is used in the ACL data structure to specify access control information for an object.
// It contains information such as the type of ACE, the access control information, and the SID of the trustee.
// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace
type ACE struct {
	// Header is the ACE header, which contains the type of ACE, flags, and size.
	Header *ACEHeader
	// AccessMask is the access mask containing the access rights that are being granted or denied.
	// It is a combination of the standard access rights and the specific rights defined by the object.
	// See https://docs.microsoft.com/en-us/windows/win32/consent/access-mask-format
	AccessMask uint32
	// SID is the SID of the trustee, which is the user or group that the ACE is granting or denying access to.
	SID *SID
}

// String returns a string representation of the ACE.
func (e *ACE) String() string {
	if e == nil || e.Header == nil {
		return "NULL"
	}

	// Get ACE type string
	var aceTypeStr string
	switch e.Header.AceType {
	case ACCESS_ALLOWED_ACE_TYPE:
		aceTypeStr = "A"
	case ACCESS_DENIED_ACE_TYPE:
		aceTypeStr = "D"
	case SYSTEM_AUDIT_ACE_TYPE:
		aceTypeStr = "AU"
	default:
		aceTypeStr = fmt.Sprintf("0x%02X", e.Header.AceType)
	}

	// Convert flags to string
	var flagsStr string
	if e.Header.AceType == SYSTEM_AUDIT_ACE_TYPE {
		if e.Header.AceFlags&SUCCESSFUL_ACCESS_ACE != 0 {
			flagsStr += "SA"
		}
		if e.Header.AceFlags&FAILED_ACCESS_ACE != 0 {
			flagsStr += "FA"
		}
	}

	// Add inheritance flags
	if e.Header.AceFlags&OBJECT_INHERIT_ACE != 0 {
		flagsStr += "OI"
	}
	if e.Header.AceFlags&CONTAINER_INHERIT_ACE != 0 {
		flagsStr += "CI"
	}
	if e.Header.AceFlags&INHERIT_ONLY_ACE != 0 {
		flagsStr += "IO"
	}
	if e.Header.AceFlags&INHERITED_ACE != 0 {
		flagsStr += "ID"
	}

	// Format access mask, checking for well-known combinations first
	var accessStr string
	if wka, ok := wellKnownAccessMasks[e.AccessMask]; ok {
		accessStr = wka
	} else {
		accessStr = fmt.Sprintf("0x%x", e.AccessMask)
	}

	// Return formatted string
	return fmt.Sprintf("(%s;%s;%s;;;%s)", aceTypeStr, flagsStr, accessStr, e.SID.String())
}

// ParseSecurityDescriptorBinary takes a binary security descriptor in relative format (contiguous memory with offsets)
func ParseSecurityDescriptorBinary(data []byte) (*SecurityDescriptor, error) {
	dataLen := uint32(len(data))
	if dataLen < 20 {
		return nil, fmt.Errorf("invalid security descriptor: it must be 20 bytes length at minimum")
	}

	revision := data[0]
	sbzl := data[1]
	control := binary.LittleEndian.Uint16(data[2:4])
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	saclOffset := binary.LittleEndian.Uint32(data[12:16])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	if ownerOffset > 0 && ownerOffset >= dataLen {
		return nil, fmt.Errorf("invalid security descriptor: Owner offset 0x%x exceeds data length 0x%x", ownerOffset, dataLen)
	}
	if groupOffset > 0 && groupOffset >= dataLen {
		return nil, fmt.Errorf("invalid security descriptor: Group offset 0x%x exceeds data length 0x%x", groupOffset, dataLen)
	}
	if saclOffset > 0 && saclOffset >= dataLen {
		return nil, fmt.Errorf("invalid security descriptor: SACL offset 0x%x exceeds data length 0x%x", saclOffset, dataLen)
	}
	if daclOffset > 0 && daclOffset >= dataLen {
		return nil, fmt.Errorf("invalid security descriptor: DACL offset 0x%x exceeds data length 0x%x", daclOffset, dataLen)
	}

	// Parse Owner SID if present
	var ownerSID *SID
	if ownerOffset > 0 {
		sid, err := parseSIDBinary(data[ownerOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing owner SID: %w", err)
		}
		ownerSID = sid
	}

	// Parse Group SID if present
	var groupSID *SID
	if groupOffset > 0 {
		sid, err := parseSIDBinary(data[groupOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing group SID: %w", err)
		}
		groupSID = sid
	}

	// Parse DACL if present
	var dacl *ACL
	if daclOffset > 0 {
		acl, err := parseACLBinary(data[daclOffset:], "D", control)
		if err != nil {
			return nil, fmt.Errorf("error parsing DACL: %w", err)
		}
		dacl = acl
	}

	// Parse SACL if present
	var sacl *ACL
	if saclOffset > 0 {
		acl, err := parseACLBinary(data[saclOffset:], "S", control)
		if err != nil {
			return nil, fmt.Errorf("error parsing SACL: %w", err)
		}
		sacl = acl
	}

	return &SecurityDescriptor{
		Revision:    revision,
		Sbzl:        sbzl,
		Control:     control,
		OwnerOffset: ownerOffset,
		GroupOffset: groupOffset,
		SaclOffset:  saclOffset,
		DaclOffset:  daclOffset,
		OwnerSID:    ownerSID,
		GroupSID:    groupSID,
		DACL:        dacl,
		SACL:        sacl,
	}, nil
}

// parseSIDBinary takes a binary SID and returns a SID struct
func parseSIDBinary(data []byte) (*SID, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("invalid SID: it must be at least 8 bytes long")
	}

	revision := data[0]
	subAuthorityCount := int(data[1])

	neededLen := 8 + (4 * subAuthorityCount)
	if len(data) < neededLen {
		return nil, fmt.Errorf("invalid SID: truncated data, got %d bytes but need %d bytes for %d sub-authorities",
			len(data), neededLen, subAuthorityCount)
	}

	if subAuthorityCount > 15 { // Maximum sub-authorities in a valid SID
		return nil, fmt.Errorf("invalid SID: too many sub-authorities (%d), maximum is 15", subAuthorityCount)
	}

	if len(data) < 8+4*subAuthorityCount {
		return nil, fmt.Errorf("invalid SID: data too short for sub-authority count")
	}

	// Parse authority (48 bits)
	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[i])
	}

	// Parse sub-authorities
	subAuthorities := make([]uint32, subAuthorityCount)
	for i := 0; i < subAuthorityCount; i++ {
		offset := 8 + 4*i
		subAuthorities[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	return &SID{
		Revision:            revision,
		IdentifierAuthority: authority,
		SubAuthority:        subAuthorities,
	}, nil
}

// parseACLBinary takes a binary ACL and returns an ACL struct
func parseACLBinary(data []byte, aclType string, control uint16) (*ACL, error) {
	dataLength := uint16(len(data))
	if dataLength < 8 {
		return nil, fmt.Errorf("invalid ACL: too short")
	}

	aclRevision := data[0]
	sbzl := data[1]
	aclSize := binary.LittleEndian.Uint16(data[2:4])
	aceCount := binary.LittleEndian.Uint16(data[4:6])
	sbz2 := binary.LittleEndian.Uint16(data[6:8])

	var aces []ACE
	offset := uint16(8)

	// Parse each ACE
	for i := uint16(0); i < aceCount; i++ {
		if offset >= aclSize {
			return nil, fmt.Errorf("invalid ACL: offset is bigger than AclSize: offset 0x%x (ACL Size: 0x%x)", offset, aclSize)
		}

		ace, err := parseACEBinary(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing ACE: %w", err)
		}

		aces = append(aces, *ace)
		offset += uint16(ace.Header.AceSize)
	}

	return &ACL{
		AclRevision: aclRevision,
		Sbzl:        sbzl,
		AclSize:     aclSize,
		AceCount:    aceCount,
		Sbz2:        sbz2,
		AclType:     aclType,
		Control:     control,
		ACEs:        aces,
	}, nil
}

// parseACEBinary takes a binary ACE and returns an ACE struct
func parseACEBinary(data []byte) (*ACE, error) {
	dataLen := uint16(len(data))
	if dataLen < 16 {
		return nil, fmt.Errorf("invalid ACE: too short, got %d bytes but need at least 16 (4 for header + 4 for access mask + 8 for SID)", dataLen)
	}

	aceType := data[0]
	aceFlags := data[1]
	aceSize := binary.LittleEndian.Uint16(data[2:4])

	// Validate full ACE size fits in data provided
	if dataLen < aceSize {
		return nil, fmt.Errorf("invalid ACE: data length %d doesn't match ACE size %d", dataLen, aceSize)
	}

	accessMask := binary.LittleEndian.Uint32(data[4:8])

	sid, err := parseSIDBinary(data[8:])
	if err != nil {
		return nil, fmt.Errorf("error parsing ACE SID: %w", err)
	}

	return &ACE{
		Header: &ACEHeader{
			AceType:  aceType,
			AceFlags: aceFlags,
			AceSize:  aceSize,
		},
		AccessMask: accessMask,
		SID:        sid,
	}, nil
}
