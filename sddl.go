package sddl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Define common errors
var (
	ErrInvalidSIDFormat      = errors.New("invalid SID format")
	ErrInvalidRevision       = errors.New("invalid SID revision")
	ErrInvalidAuthority      = errors.New("invalid authority value")
	ErrTooManySubAuthorities = errors.New("too many sub-authorities")
	ErrInvalidSubAuthority   = errors.New("invalid sub-authority value")
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

// reverseWellKnownSids maps short SID names to their full string representation
var reverseWellKnownSids = make(map[string]string)

// reverseWellKnownAccessMasks maps access masks to their short names
var reverseWellKnownAccessMasks = make(map[string]uint32)

func init() {
	// Initialize the reverse mapping of wellKnownSids
	for k, v := range wellKnownSids {
		reverseWellKnownSids[v] = k
	}

	// Initialize the reverse mapping of wellKnownAccessMasks
	for k, v := range wellKnownAccessMasks {
		reverseWellKnownAccessMasks[v] = k
	}
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
		if a.Control&SE_DACL_AUTO_INHERIT_RE != 0 {
			aclFlags = append(aclFlags, "AR")
		}
		if a.Control&SE_DACL_DEFAULTED != 0 {
			aclFlags = append(aclFlags, "R")
		}
	} else if a.AclType == "S" {
		if a.Control&SE_SACL_PROTECTED != 0 {
			aclFlags = append(aclFlags, "P")
		}
		if a.Control&SE_SACL_AUTO_INHERITED != 0 {
			aclFlags = append(aclFlags, "AI")
		}
		if a.Control&SE_SACL_AUTO_INHERIT_RE != 0 {
			aclFlags = append(aclFlags, "AR")
		}
		if a.Control&SE_SACL_DEFAULTED != 0 {
			aclFlags = append(aclFlags, "R")
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

// parseAccessMask converts an access mask string to its corresponding uint32 value
func parseAccessMask(maskStr string) (uint32, error) {
	// Check well-known access masks first
	if value, ok := reverseWellKnownAccessMasks[maskStr]; ok {
		return value, nil
	}

	// If not a well-known mask, try to parse as hexadecimal
	if strings.HasPrefix(maskStr, "0x") {
		value, err := strconv.ParseUint(maskStr[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid hexadecimal access mask: %s", maskStr)
		}
		return uint32(value), nil
	}

	return 0, fmt.Errorf("unknown access mask: %s", maskStr)
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

// parseACEString parses an ACE string in the format "(type;flags;rights;;;sid)" into an ACE structure
// Example: "(A;;FA;;;SY)" which represents:
// - Type: A (ACCESS_ALLOWED_ACE_TYPE)
// - Flags: (none)
// - Rights: FA (Full Access)
// - SID: SY (Local System)
func parseACEString(aceStr string) (*ACE, error) {
	// Validate basic string format
	if len(aceStr) < 2 || !strings.HasPrefix(aceStr, "(") || !strings.HasSuffix(aceStr, ")") {
		return nil, fmt.Errorf("invalid ACE string format: must be enclosed in parentheses")
	}

	// Remove parentheses and split into components
	parts := strings.Split(aceStr[1:len(aceStr)-1], ";")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid ACE string format: expected 6 components separated by semicolons")
	}

	// Parse ACE type
	aceType, err := parseACEType(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ACE type: %w", err)
	}

	// Parse ACE flags with type validation
	aceFlags, err := parseFlagsForACEType(parts[1], aceType)
	if err != nil {
		return nil, fmt.Errorf("invalid ACE flags: %w", err)
	}

	// Parse access mask
	accessMask, err := parseAccessMask(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid access mask: %w", err)
	}

	// Parse SID (parts[3] and parts[4] are object type and inherited object type, which we ignore)
	sid, err := parseSIDString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid SID: %w", err)
	}

	// Calculate the total size of the ACE
	// Size = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + size of the SID
	// SID size = 8 + (4 * number of sub-authorities)
	sidSize := 8 + (4 * len(sid.SubAuthority))
	aceSize := 4 + 4 + sidSize // 4 (header) + 4 (access mask) + sidSize

	ace := &ACE{
		Header: &ACEHeader{
			AceType:  aceType,
			AceFlags: aceFlags,
			AceSize:  uint16(aceSize),
		},
		AccessMask: accessMask,
		SID:        sid,
	}

	return ace, nil
}

// parseACEType converts an ACE type string to its corresponding byte value
func parseACEType(typeStr string) (byte, error) {
	// First check well-known string representations
	switch typeStr {
	case "A":
		return ACCESS_ALLOWED_ACE_TYPE, nil
	case "D":
		return ACCESS_DENIED_ACE_TYPE, nil
	case "AU":
		return SYSTEM_AUDIT_ACE_TYPE, nil
	case "AL":
		return SYSTEM_ALARM_ACE_TYPE, nil
	case "OA":
		return ACCESS_ALLOWED_OBJECT_ACE_TYPE, nil
	}

	// If not a well-known type, try to parse as hexadecimal
	// The format should be "0xNN" where NN is a hex number
	if strings.HasPrefix(typeStr, "0x") {
		value, err := strconv.ParseUint(typeStr[2:], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid hexadecimal ACE type: %s", typeStr)
		}
		return byte(value), nil
	}

	return 0, fmt.Errorf("invalid ACE type: %s (must be a known type or hexadecimal value)", typeStr)
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

// parseACLFlags splits a flag string into individualn ACL flags
// Example: "PAI" becomes []string{"P", "AI"}
//
// The ACL Control Flags in SDDL String Format are:
//
// Single-letter flags:
//
//	P - Protected
//	    Prevents the ACL from being modified by inheritable ACEs.
//	    The ACL is protected from inheritance flowing down from parent containers.
//	R - Read-Only
//	    Marks the ACL as read-only, preventing any modifications.
//	    This is often used for system-managed ACLs.
//
// Two-letter flags:
//
//	AI - Auto-Inherited
//	    Indicates the ACL was created through inheritance.
//	    Appears when the ACL contains entries inherited from a parent object.
//	AR - Auto-Inherit Required
//	    Forces child objects to inherit this ACL.
//	    When set, ensures all child objects must process inherited permissions.
//	NO - No Inheritance
//	    Explicitly excludes inheritable ACEs from being considered.
//	    Blocks inheritance without changing the inherited ACEs themselves.
//	IO - Inherit Only
//	    Specifies the ACL should only be used for inheritance purposes.
//	    The ACL is not used for access checks on the current object.
//
// These flags can be combined in any order after the ACL type identifier:
// - For DACLs: "D:[flags]", e.g., "D:PAI", "D:AINO"
// - For SACLs: "S:[flags]", e.g., "S:PAR", "S:ARNO"
//
// The ordering of combined flags does not affect their meaning:
// "D:AINO" is equivalent to "D:NOAI"
func parseACLFlags(s string) ([]string, error) {
	var flags []string
	for i := 0; i < len(s); {
		code1 := s[i : i+1]
		code2 := ""
		if i+1 < len(s) {
			code2 = s[i : i+2]
		}

		// Check for two-character flags first
		switch code2 {
		case "AI", "AR", "NO", "IO":
			flags = append(flags, code2)
			i += 2
		default:
			// Check for single-character flags
			switch code1 {
			case "P", "R":
				flags = append(flags, code1)
				i++
			default:
				return nil, fmt.Errorf("invalid flag: %q", s[i])
			}
		}
	}
	return flags, nil
}

// parseACLString parses an ACL string representation into an ACL structure.
// The ACL string format follows the Security Descriptor String Format (SDDL)
// where:
// - ACL type is indicated by the prefix (D: for DACL, S: for SACL)
// - Optional flags may follow the prefix (e.g., "PAI" for Protected and AutoInherited)
// - ACEs are enclosed in parentheses
// Examples:
//   - "D:(A;;FA;;;SY)"            // DACL with a single ACE
//   - "S:PAI(AU;SA;FA;;;SY)"      // Protected auto-inherited SACL with an audit ACE
//   - "D:(A;;FA;;;SY)(D;;FR;;;WD)" // DACL with two ACEs
func parseACLString(s string) (*ACL, error) {
	// Handle empty ACL string
	if len(s) == 0 {
		return nil, fmt.Errorf("empty ACL string")
	}

	// String must be at least 2 characters (D: or S:)
	if len(s) < 2 || s[1] != ':' {
		return nil, fmt.Errorf("invalid ACL string format: must start with 'D:' or 'S:'")
	}

	// Determine ACL type from prefix
	var aclType string
	var baseControl uint16
	switch s[0] {
	case 'D':
		aclType = "D"
		baseControl = SE_DACL_PRESENT
	case 'S':
		aclType = "S"
		baseControl = SE_SACL_PRESENT
	default:
		return nil, fmt.Errorf("invalid ACL type: must start with 'D:' or 'S:'")
	}

	// Remove prefix for further processing
	s = s[2:]

	// Parse flags if present (before the first ACE)
	var control uint16 = baseControl
	var flags []string
	aceStart := 0

	// Look for flags section (between : and first parenthesis)
	if len(s) > 0 && s[0] != '(' {
		flagEnd := strings.Index(s, "(")
		if flagEnd == -1 {
			if strings.Contains(s, ")") {
				return nil, fmt.Errorf("invalid ACL format: missing opening parenthesis")
			}
			flagEnd = len(s)
		}
		ff, err := parseACLFlags(s[:flagEnd])
		if err != nil {
			return nil, fmt.Errorf("error parsing flags: %w", err)
		}
		flags = ff
		aceStart = flagEnd
	}

	// Update control flags based on parsed flags
	// Note: other flags such as NO, IO, etc. are ignored because they do not have a corresponding control flag
	for _, flag := range flags {
		switch flag {
		case "P":
			if aclType == "D" {
				control |= SE_DACL_PROTECTED
			} else {
				control |= SE_SACL_PROTECTED
			}
		case "AI":
			if aclType == "D" {
				control |= SE_DACL_AUTO_INHERITED
			} else {
				control |= SE_SACL_AUTO_INHERITED
			}
		case "AR":
			if aclType == "D" {
				control |= SE_DACL_AUTO_INHERIT_RE
			} else {
				control |= SE_SACL_AUTO_INHERIT_RE
			}
		case "R":
			if aclType == "D" {
				control |= SE_DACL_DEFAULTED
			} else {
				control |= SE_SACL_DEFAULTED
			}
		}
	}

	// Parse ACEs
	var aces []ACE
	remaining := s[aceStart:]

	// Handle empty ACL (no ACEs)
	if len(remaining) == 0 {
		return &ACL{
			AclRevision: 2,
			AclSize:     8, // Size of empty ACL (just header)
			AclType:     aclType,
			Control:     control,
		}, nil
	}

	// Extract each ACE string (enclosed in parentheses)
	for len(remaining) > 0 {
		if remaining[0] != '(' {
			return nil, fmt.Errorf("invalid ACE format: expected '(' but got %q", remaining[0])
		}

		// Find closing parenthesis
		closePos := strings.Index(remaining, ")")
		if closePos == -1 {
			return nil, fmt.Errorf("invalid ACE format: missing closing parenthesis")
		}

		// Parse individual ACE
		aceStr := remaining[:closePos+1]
		ace, err := parseACEString(aceStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing ACE %q: %w", aceStr, err)
		}

		aces = append(aces, *ace)
		remaining = remaining[closePos+1:]
	}

	// Calculate total ACL size
	totalSize := 8 // ACL header size
	for _, ace := range aces {
		totalSize += int(ace.Header.AceSize)
	}

	// Create and return the ACL structure
	return &ACL{
		AclRevision: 2,
		Sbzl:        0,
		AclSize:     uint16(totalSize),
		AceCount:    uint16(len(aces)),
		Sbz2:        0,
		AclType:     aclType,
		Control:     control,
		ACEs:        aces,
	}, nil
}

// parseFlagsForACEType converts an ACE flags string to its corresponding byte value,
// validating that the flags are appropriate for the given ACE type
func parseFlagsForACEType(flagsStr string, aceType byte) (byte, error) {
	if flagsStr == "" {
		return 0, nil
	}

	var flags byte
	var hasAuditFlags bool

	// Process flags in pairs (each flag is 2 characters)
	for i := 0; i < len(flagsStr); i += 2 {
		if i+2 > len(flagsStr) {
			return 0, fmt.Errorf("invalid flag format at position %d", i)
		}

		flag := flagsStr[i : i+2]
		switch flag {
		// Inheritance flags - valid for all ACE types
		case "CI":
			flags |= CONTAINER_INHERIT_ACE
		case "OI":
			flags |= OBJECT_INHERIT_ACE
		case "NP":
			flags |= NO_PROPAGATE_INHERIT_ACE
		case "IO":
			flags |= INHERIT_ONLY_ACE
		case "ID":
			flags |= INHERITED_ACE
		// Audit flags - only valid for SYSTEM_AUDIT_ACE_TYPE
		case "SA", "FA":
			hasAuditFlags = true
			if aceType != SYSTEM_AUDIT_ACE_TYPE {
				return 0, fmt.Errorf("audit flags (SA/FA) are only valid for audit ACEs")
			}
			if flag == "SA" {
				flags |= SUCCESSFUL_ACCESS_ACE
			} else {
				flags |= FAILED_ACCESS_ACE
			}
		default:
			return 0, fmt.Errorf("unknown flag: %s", flag)
		}
	}

	// Validate that audit ACEs have at least one audit flag
	if aceType == SYSTEM_AUDIT_ACE_TYPE && !hasAuditFlags {
		return 0, fmt.Errorf("audit ACEs must specify at least one audit flag (SA/FA)")
	}

	return flags, nil
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

// parseSIDString parses a string SID representation into a SID structure
func parseSIDString(s string) (*SID, error) {
	// First, check if it's a well-known SID abbreviation
	if fullSid, ok := reverseWellKnownSids[s]; ok {
		s = fullSid
	}

	// If it doesn't start with "S-", it's invalid
	if !strings.HasPrefix(s, "S-") {
		return nil, fmt.Errorf("%w: must start with S-", ErrInvalidSIDFormat)
	}

	// Split the SID string into components
	parts := strings.Split(s[2:], "-") // Skip "S-" prefix
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: insufficient components", ErrInvalidSIDFormat)
	}

	// Parse revision
	revision, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRevision, err)
	}
	if revision != 1 {
		return nil, fmt.Errorf("%w: got %d, want 1", ErrInvalidRevision, revision)
	}

	// Parse authority - can be decimal or hex (with 0x prefix)
	var authority uint64
	authStr := parts[1]
	if strings.HasPrefix(strings.ToLower(authStr), "0x") {
		// Parse hexadecimal authority
		authority, err = strconv.ParseUint(authStr[2:], 16, 48)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid hex value %v", ErrInvalidAuthority, err)
		}
	} else {
		// Parse decimal authority
		authority, err = strconv.ParseUint(authStr, 10, 48)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid decimal value %v", ErrInvalidAuthority, err)
		}
	}

	// Additional validation for authority value
	if authority >= 1<<48 {
		return nil, fmt.Errorf("%w: value %d exceeds maximum of 2^48-1", ErrInvalidAuthority, authority)
	}

	// Parse sub-authorities
	subAuthCount := len(parts) - 2 // Subtract revision and authority parts
	if subAuthCount > 15 {
		return nil, fmt.Errorf("%w: got %d, maximum is 15", ErrTooManySubAuthorities, subAuthCount)
	}

	subAuthorities := make([]uint32, subAuthCount)
	for i := 0; i < subAuthCount; i++ {
		sa, err := strconv.ParseUint(parts[i+2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid sub-authority at position %d: %v",
				ErrInvalidSubAuthority, i, err)
		}
		subAuthorities[i] = uint32(sa)
	}

	return &SID{
		Revision:            byte(revision),
		IdentifierAuthority: authority,
		SubAuthority:        subAuthorities,
	}, nil
}
