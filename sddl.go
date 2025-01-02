package sddl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
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

// accessMaskComponents maps permission codes to their bit values
var accessMaskComponents = map[string]uint32{
	// Generic Rights (0xF0000000)
	"GA": 0x10000000, // Generic All
	"GX": 0x20000000, // Generic Execute
	"GW": 0x40000000, // Generic Write
	"GR": 0x80000000, // Generic Read

	// ??
	"MA": 0x02000000, // Maximum Allowed
	"AS": 0x01000000, // Access System Security

	// Standard Rights (0x001F0000)
	"SY": 0x00100000, // Synchronize
	"WO": 0x00080000, // Write Owner
	"WD": 0x00040000, // Write DAC
	"RC": 0x00020000, // Read Control
	"SD": 0x00010000, // Delete

	// Directory Service Object Access Rights (0x0000FFFF)
	"CR": 0x00000100, // Control Access
	"LO": 0x00000080, // List Object
	"DT": 0x00000040, // Delete Tree
	"WP": 0x00000020, // Write Property
	"RP": 0x00000010, // Read Property
	"SW": 0x00000008, // Self Write
	"LC": 0x00000004, // List Children
	"DC": 0x00000002, // Delete Child
	"CC": 0x00000001, // Create Child
}

// WellKnownAccessMasks maps common combined access masks to their string representations
var wellKnownAccessMasks = map[uint32]string{
	0x001f01ff: "FA", // File All (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
	0x00120089: "FR", // File Read (READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE)
	0x00120116: "FW", // File Write (READ_CONTROL | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)
	0x001200a0: "FX", // File Execute (READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE)
}

var reversedAccessMaskComponents = make(map[uint32]string)

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

	// Initialize the reverse mapping of accessMaskComponents
	for k, v := range accessMaskComponents {
		reversedAccessMaskComponents[v] = k
	}
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

// Binary converts an ACE structure to its binary representation following Windows format.
// The binary format is:
// - ACE Header:
//   - AceType (1 byte)
//   - AceFlags (1 byte)
//   - AceSize (2 bytes, little-endian)
//
// - AccessMask (4 bytes, little-endian)
// - SID in binary format (variable size)
func (e *ACE) Binary() ([]byte, error) {
	// Validate ACE structure
	if e == nil {
		return nil, fmt.Errorf("cannot convert nil ACE to binary")
	}
	if e.Header == nil {
		return nil, fmt.Errorf("cannot convert ACE with nil header to binary")
	}
	if e.SID == nil {
		return nil, fmt.Errorf("cannot convert ACE with nil SID to binary")
	}

	// Convert SID to binary first to get its size
	sidBinary, err := e.SID.Binary()
	if err != nil {
		return nil, fmt.Errorf("error converting SID to binary: %w", err)
	}

	// Calculate total ACE size: 4 (header) + 4 (access mask) + len(sidBinary)
	aceSize := 4 + 4 + len(sidBinary)
	if aceSize > 65535 { // Check if size fits in uint16
		return nil, fmt.Errorf("ACE size %d exceeds maximum size of 65535 bytes", aceSize)
	}

	// Validate that the calculated size matches the header size
	if uint16(aceSize) != e.Header.AceSize {
		return nil, fmt.Errorf("calculated ACE size %d doesn't match header size %d",
			aceSize, e.Header.AceSize)
	}

	// Create result buffer
	result := make([]byte, aceSize)

	// Set ACE header
	result[0] = e.Header.AceType
	result[1] = e.Header.AceFlags
	binary.LittleEndian.PutUint16(result[2:4], uint16(aceSize))

	// Set access mask (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(result[4:8], e.AccessMask)

	// Copy SID binary representation
	copy(result[8:], sidBinary)

	return result, nil
}

// String returns a string representation of the ACE.
func (e *ACE) String() (string, error) {
	if e == nil || e.Header == nil {
		return "NULL", nil
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
	if value, ok := wellKnownAccessMasks[e.AccessMask]; ok {
		accessStr = value
	} else {
		maskComponents, remainingMask := decomposeAccessMask(e.AccessMask)
		accessStr = strings.Join(maskComponents, "")
		if remainingMask != 0 {
			accessStr = fmt.Sprintf("0x%08X", e.AccessMask)
		}
	}

	// Return formatted string
	sidStr, err := e.SID.String()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("(%s;%s;%s;;;%s)", aceTypeStr, flagsStr, accessStr, sidStr), nil
}

// ACEHeader represents the Windows ACE_HEADER structure
type ACEHeader struct {
	AceType  byte   // ACE type (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, etc.)
	AceFlags byte   // ACE flags (OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, etc.)
	AceSize  uint16 // Total size of the ACE in bytes
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

// Binary converts an ACL structure to its binary representation following Windows format.
// The binary format consists of:
// - ACL Header:
//   - Revision (1 byte)
//   - Sbz1 (1 byte, reserved)
//   - AclSize (2 bytes, little-endian)
//   - AceCount (2 bytes, little-endian)
//   - Sbz2 (2 bytes, reserved)
//
// - Array of ACEs in binary format (variable size)
func (a *ACL) Binary() ([]byte, error) {
	// Validate ACL structure
	if a == nil {
		return nil, fmt.Errorf("cannot convert nil ACL to binary")
	}

	// Convert all ACEs to binary first to validate them and calculate total size
	aceBinaries := make([][]byte, len(a.ACEs))
	totalAceSize := 0

	for i := range a.ACEs {
		aceBinary, err := a.ACEs[i].Binary()
		if err != nil {
			return nil, fmt.Errorf("error converting ACE %d to binary: %w", i, err)
		}
		aceBinaries[i] = aceBinary
		totalAceSize += len(aceBinary)
	}

	// Calculate total ACL size: 8 (header) + sum of ACE sizes
	aclSize := 8 + totalAceSize
	if aclSize > 65535 { // Check if size fits in uint16
		return nil, fmt.Errorf("ACL size %d exceeds maximum size of 65535 bytes", aclSize)
	}

	// Validate that calculated size matches the ACL size field
	if uint16(aclSize) != a.AclSize {
		return nil, fmt.Errorf("calculated ACL size %d doesn't match header size %d",
			aclSize, a.AclSize)
	}

	// Validate ACE count
	if uint16(len(a.ACEs)) != a.AceCount {
		return nil, fmt.Errorf("actual ACE count %d doesn't match header count %d",
			len(a.ACEs), a.AceCount)
	}

	// Create result buffer
	result := make([]byte, aclSize)

	// Set ACL header
	result[0] = a.AclRevision
	result[1] = a.Sbzl // Reserved byte
	binary.LittleEndian.PutUint16(result[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(result[4:6], uint16(len(a.ACEs)))
	binary.LittleEndian.PutUint16(result[6:8], a.Sbz2) // Reserved bytes

	// Copy each ACE's binary representation
	offset := 8
	for _, aceBinary := range aceBinaries {
		copy(result[offset:], aceBinary)
		offset += len(aceBinary)
	}

	return result, nil
}

func (a *ACL) String() (string, error) {
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
		aceStr, err := ace.String()
		if err != nil {
			return "", err
		}
		aces = append(aces, aceStr)
	}

	var result string
	if len(aclFlags) > 0 {
		result = fmt.Sprintf("%s:%s", a.AclType, strings.Join(aclFlags, ""))
	} else {
		result = fmt.Sprintf("%s:", a.AclType)
	}

	return result + strings.Join(aces, ""), nil
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

// Binary converts a SecurityDescriptor structure to its binary representation in self-relative format.
// The binary format consists of:
// - Fixed part:
//   - Revision (1 byte)
//   - Sbz1 (1 byte, reserved)
//   - Control (2 bytes, little-endian)
//   - OwnerOffset (4 bytes, little-endian)
//   - GroupOffset (4 bytes, little-endian)
//   - SaclOffset (4 bytes, little-endian)
//   - DaclOffset (4 bytes, little-endian)
//
// - Variable part (in canonical order):
//   - Owner SID
//   - Group SID
//   - SACL
//   - DACL
func (sd *SecurityDescriptor) Binary() ([]byte, error) {
	// Validate security descriptor structure
	if sd == nil {
		return nil, fmt.Errorf("cannot convert nil SecurityDescriptor to binary")
	}

	// Force SE_SELF_RELATIVE flag as we're creating a self-relative security descriptor
	sd.Control |= SE_SELF_RELATIVE

	// Convert all components to binary first to calculate total size and validate
	var ownerBinary, groupBinary, saclBinary, daclBinary []byte
	var err error

	// Convert Owner SID if present
	if sd.OwnerSID != nil {
		ownerBinary, err = sd.OwnerSID.Binary()
		if err != nil {
			return nil, fmt.Errorf("error converting Owner SID to binary: %w", err)
		}
	}

	// Convert Group SID if present
	if sd.GroupSID != nil {
		groupBinary, err = sd.GroupSID.Binary()
		if err != nil {
			return nil, fmt.Errorf("error converting Group SID to binary: %w", err)
		}
	}

	// Convert SACL if present and control flags indicate it should be
	if sd.SACL != nil {
		if sd.Control&SE_SACL_PRESENT == 0 {
			return nil, fmt.Errorf("SACL present but SE_SACL_PRESENT flag not set")
		}
		saclBinary, err = sd.SACL.Binary()
		if err != nil {
			return nil, fmt.Errorf("error converting SACL to binary: %w", err)
		}
	} else if sd.Control&SE_SACL_PRESENT != 0 {
		return nil, fmt.Errorf("SE_SACL_PRESENT flag set but SACL is nil")
	}

	// Convert DACL if present and control flags indicate it should be
	if sd.DACL != nil {
		if sd.Control&SE_DACL_PRESENT == 0 {
			return nil, fmt.Errorf("DACL present but SE_DACL_PRESENT flag not set")
		}
		daclBinary, err = sd.DACL.Binary()
		if err != nil {
			return nil, fmt.Errorf("error converting DACL to binary: %w", err)
		}
	} else if sd.Control&SE_DACL_PRESENT != 0 {
		return nil, fmt.Errorf("SE_DACL_PRESENT flag set but DACL is nil")
	}

	// Calculate total size: 20 (fixed header) + sizes of all components
	totalSize := 20 + len(ownerBinary) + len(groupBinary) + len(saclBinary) + len(daclBinary)

	// Create result buffer
	result := make([]byte, totalSize)

	// Set fixed header
	result[0] = sd.Revision
	result[1] = sd.Sbzl
	binary.LittleEndian.PutUint16(result[2:4], sd.Control)

	// Initialize current offset for variable part
	currentOffset := 20

	// Set Owner SID and its offset if present
	if ownerBinary != nil {
		binary.LittleEndian.PutUint32(result[4:8], uint32(currentOffset))
		copy(result[currentOffset:], ownerBinary)
		currentOffset += len(ownerBinary)
	}

	// Set Group SID and its offset if present
	if groupBinary != nil {
		binary.LittleEndian.PutUint32(result[8:12], uint32(currentOffset))
		copy(result[currentOffset:], groupBinary)
		currentOffset += len(groupBinary)
	}

	// Set SACL and its offset if present
	if saclBinary != nil {
		binary.LittleEndian.PutUint32(result[12:16], uint32(currentOffset))
		copy(result[currentOffset:], saclBinary)
		currentOffset += len(saclBinary)
	}

	// Set DACL and its offset if present
	if daclBinary != nil {
		binary.LittleEndian.PutUint32(result[16:20], uint32(currentOffset))
		copy(result[currentOffset:], daclBinary)
	}

	return result, nil
}

func (sd *SecurityDescriptor) String() (string, error) {
	var parts []string
	if sd.OwnerSID != nil {
		ownerSIDString, err := sd.OwnerSID.String()
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("O:%s", ownerSIDString))
	}
	if sd.GroupSID != nil {
		groupSIDString, err := sd.GroupSID.String()
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("G:%s", groupSIDString))
	}
	if sd.DACL != nil {
		daclStr, err := sd.DACL.String()
		if err != nil {
			return "", err
		}
		parts = append(parts, daclStr)
	}
	if sd.SACL != nil {
		saclStr, err := sd.SACL.String()
		if err != nil {
			return "", err
		}
		parts = append(parts, saclStr)
	}
	return strings.Join(parts, ""), nil
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

// Binary converts a SID structure to its binary representation following Windows format.
// The binary format is:
// - Revision (1 byte)
// - SubAuthorityCount (1 byte)
// - IdentifierAuthority (6 bytes, big-endian)
// - SubAuthorities (4 bytes each, little-endian)
func (s *SID) Binary() ([]byte, error) {
	// Validate SID structure
	if s == nil {
		return nil, fmt.Errorf("cannot convert nil SID to binary")
	}

	if s.Revision != 1 {
		return nil, fmt.Errorf("%w: revision must be 1, was %d", ErrInvalidSIDFormat, s.Revision)
	}

	// Check number of sub-authorities (maximum is 15 in Windows)
	if len(s.SubAuthority) > 15 {
		return nil, fmt.Errorf("%w: got %d, maximum is 15",
			ErrTooManySubAuthorities, len(s.SubAuthority))
	}

	// Check authority value fits in 48 bits
	if s.IdentifierAuthority >= 1<<48 {
		return nil, fmt.Errorf("%w: value %d exceeds maximum of 2^48-1",
			ErrInvalidAuthority, s.IdentifierAuthority)
	}

	// Calculate total size:
	// 1 byte revision + 1 byte count + 6 bytes authority + (4 bytes × number of sub-authorities)
	size := 8 + (4 * len(s.SubAuthority))
	result := make([]byte, size)

	// Set revision
	result[0] = s.Revision

	// Set sub-authority count
	result[1] = byte(len(s.SubAuthority))

	// Set authority value - convert uint64 to 6 bytes in big-endian order
	// We're using big-endian because Windows stores the authority as a 6-byte
	// value in network byte order (big-endian)
	auth := s.IdentifierAuthority
	for i := 7; i >= 2; i-- {
		result[i] = byte(auth & 0xFF)
		auth >>= 8
	}

	// Set sub-authorities in little-endian order
	// Windows stores these as 32-bit integers in little-endian format
	for i, subAuth := range s.SubAuthority {
		offset := 8 + (4 * i)
		binary.LittleEndian.PutUint32(result[offset:], subAuth)
	}

	return result, nil
}

// String returns a string representation of the SID. If the SID corresponds to a well-known
// SID, the short well-known SID name will be returned instead of the full SID string. If
// the SID is not valid, an error will be returned.
//
// The returned string will be in the format
// "S-<revision>-<authority>-<sub-authority1>-<sub-authority2>-...-<sub-authorityN>".
// If the SID is well-known, the string will be in the format "<well-known SID name>".
func (s *SID) String() (string, error) {
	// Check authority value fits in 48 bits
	if s.IdentifierAuthority >= 1<<48 {
		return "", fmt.Errorf("%w: value %d exceeds maximum of 2^48-1",
			ErrInvalidAuthority, s.IdentifierAuthority)
	}

	// Check number of sub-authorities (maximum is 15 in Windows)
	if len(s.SubAuthority) > 15 {
		return "", fmt.Errorf("%w: got %d, maximum is 15",
			ErrTooManySubAuthorities, len(s.SubAuthority))
	}

	if s.Revision != 1 {
		return "", fmt.Errorf("%w: revision must be 1, was %d", ErrInvalidSIDFormat, s.Revision)
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
		return wk, nil
	}

	return sidStr, nil
}

// decomposeAccessMask breaks down an access mask into its individual components
// it also returns the mask without the components
func decomposeAccessMask(mask uint32) ([]string, uint32) {
	var components []string

	// Check components in order (least significant bits first)
	maskValues := slices.Collect(maps.Keys(reversedAccessMaskComponents))
	slices.Sort(maskValues)
	for _, val := range maskValues {
		name := reversedAccessMaskComponents[val]
		if mask&val == val {
			components = append(components, name)
			mask ^= val
		}
	}

	return components, mask
}

// composeAccessMask combines individual permission components into an access mask
// it also return the components that were unable to be combined
func composeAccessMask(components []string) (uint32, []string) {
	var remaining []string
	var mask uint32
	for _, code := range components {
		if val, ok := accessMaskComponents[code]; ok {
			mask |= val
		} else {
			remaining = append(remaining, code)
		}
	}
	return mask, remaining
}
