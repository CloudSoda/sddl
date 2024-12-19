package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
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
	Revision byte
	Sbzl     byte
	Control  uint16
	Owner    uint32
	Group    uint32
	Sacl     uint32
	Dacl     uint32
}

// ACL represents the windows ACL structure
type ACL struct {
	AclRevision byte
	Sbzl        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// ACEHeader represents the Windows ACE_HEADER structure
type ACEHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// ParseSecurityDescriptor parses a binary security descriptor and returns its string representation
func ParseSecurityDescriptor(data []byte) (string, error) {
	dataLen := uint32(len(data))
	if dataLen < 20 {
		return "", fmt.Errorf("invalid security descriptor: it must be 20 bytes length at minimum")
	}

	sd := &SecurityDescriptor{
		Revision: data[0],
		Sbzl:     data[1],
		Control:  binary.LittleEndian.Uint16(data[2:4]),
		Owner:    binary.LittleEndian.Uint32(data[4:8]),
		Group:    binary.LittleEndian.Uint32(data[8:12]),
		Sacl:     binary.LittleEndian.Uint32(data[12:16]),
		Dacl:     binary.LittleEndian.Uint32(data[16:20]),
	}

	if sd.Owner > 0 && sd.Owner >= dataLen {
		return "", fmt.Errorf("invalid security descriptor: Owner offset 0x%x exceeds data length 0x%x", sd.Owner, dataLen)
	}
	if sd.Group > 0 && sd.Group >= dataLen {
		return "", fmt.Errorf("invalid security descriptor: Group offset 0x%x exceeds data length 0x%x", sd.Group, dataLen)
	}
	if sd.Sacl > 0 && sd.Sacl >= dataLen {
		return "", fmt.Errorf("invalid security descriptor: SACL offset 0x%x exceeds data length 0x%x", sd.Sacl, dataLen)
	}
	if sd.Dacl > 0 && sd.Dacl >= dataLen {
		return "", fmt.Errorf("invalid security descriptor: DACL offset 0x%x exceeds data length 0x%x", sd.Dacl, dataLen)
	}

	var parts []string

	// Parse Owner SID if present
	if sd.Owner > 0 {
		ownerSID, err := parseSID(data[sd.Owner:])
		if err != nil {
			return "", fmt.Errorf("error parsing owner SID: %w", err)
		}
		parts = append(parts, fmt.Sprintf("O:%s", ownerSID))
	}

	// Parse Group SID if present
	if sd.Group > 0 {
		groupSID, err := parseSID(data[sd.Group:])
		if err != nil {
			return "", fmt.Errorf("error parsing group SID: %w", err)
		}
		parts = append(parts, fmt.Sprintf("G:%s", groupSID))
	}

	// Parse DACL if present
	if sd.Control&SE_DACL_PRESENT != 0 && sd.Dacl > 0 {
		dacl, err := parseACL(data[sd.Dacl:], "D", sd.Control)
		if err != nil {
			return "", fmt.Errorf("error parsing DACL: %w", err)
		}
		parts = append(parts, dacl)
	}

	// Parse SACL if present
	if sd.Control&SE_SACL_PRESENT != 0 && sd.Sacl > 0 {
		sacl, err := parseACL(data[sd.Sacl:], "S", sd.Control)
		if err != nil {
			return "", fmt.Errorf("error parsing SACL: %w", err)
		}
		parts = append(parts, sacl)
	}

	return strings.Join(parts, ""), nil
}

func parseSID(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("invalid SID: it must be at least 8 bytes long")
	}

	revision := data[0]
	subAuthorityCount := int(data[1])

	neededLen := 8 + (4 * subAuthorityCount)
	if len(data) < neededLen {
		return "", fmt.Errorf("invalid SID: truncated data, got %d bytes but need %d bytes for %d sub-authorities",
			len(data), neededLen, subAuthorityCount)
	}

	if subAuthorityCount > 15 { // Maximum sub-authorities in a valid SID
		return "", fmt.Errorf("invalid SID: too many sub-authorities (%d), maximum is 15", subAuthorityCount)
	}

	if len(data) < 8+4*subAuthorityCount {
		return "", fmt.Errorf("invalid SID: data too short for sub-authority count")
	}

	// Parse authority (48 bits)
	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[i])
	}

	// Build SID string
	sidParts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}

	// Parse sub-authorities
	for i := 0; i < subAuthorityCount; i++ {
		offset := 8 + 4*i
		subAuth := binary.LittleEndian.Uint32(data[offset : offset+4])
		sidParts = append(sidParts, fmt.Sprintf("%d", subAuth))
	}

	sid := strings.Join(sidParts, "-")

	// Check if it's a well-known SID
	if alias, ok := wellKnownSids[sid]; ok {
		return alias, nil
	}

	return sid, nil
}

func parseACL(data []byte, aclType string, control uint16) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("invalid ACL: too short")
	}

	acl := &ACL{
		AclRevision: data[0],
		Sbzl:        data[1],
		AclSize:     binary.LittleEndian.Uint16(data[2:4]),
		AceCount:    binary.LittleEndian.Uint16(data[4:6]),
		Sbz2:        binary.LittleEndian.Uint16(data[6:8]),
	}

	var aces []string
	offset := uint16(8)

	// Add ACL flags
	var aclFlags []string
	if aclType == "D" {
		if control&SE_DACL_AUTO_INHERITED != 0 {
			aclFlags = append(aclFlags, "AI")
		}
		if control&SE_DACL_PROTECTED != 0 {
			aclFlags = append(aclFlags, "P")
		}
	} else if aclType == "S" {
		if control&SE_SACL_AUTO_INHERITED != 0 {
			aclFlags = append(aclFlags, "AI")
		}
		if control&SE_SACL_PROTECTED != 0 {
			aclFlags = append(aclFlags, "P")
		}
	}

	// Parse each ACE
	for i := uint16(0); i < acl.AceCount; i++ {
		if offset >= acl.AclSize {
			break
		}

		if offset+4 > acl.AclSize {
			return "", fmt.Errorf("invalid ACL: truncated ACE header at offset 0x%x (ACL size: 0x%x)", offset, acl.AclSize)
		}

		aceHeader := &ACEHeader{
			AceType:  data[offset],
			AceFlags: data[offset+1],
			AceSize:  binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
		}

		if aceHeader.AceSize < 4 {
			return "", fmt.Errorf("invalid ACL: ACE size too small (0x%x) at offset 0x%x", aceHeader.AceSize, offset)
		}

		if offset+aceHeader.AceSize > acl.AclSize {
			return "", fmt.Errorf("invalid ACL: ACE at offset 0x%x with size 0x%x would exceed ACL size 0x%x",
				offset, aceHeader.AceSize, acl.AclSize)
		}

		aceStr, err := parseACE(data[offset : offset+aceHeader.AceSize])
		if err != nil {
			return "", fmt.Errorf("error parsing ACE %d: %w", i, err)
		}
		aces = append(aces, aceStr)

		offset += aceHeader.AceSize
	}

	var result string
	if len(aclFlags) > 0 {
		result = fmt.Sprintf("%s:%s", aclType, strings.Join(aclFlags, ""))
	} else {
		result = fmt.Sprintf("%s:", aclType)
	}

	return result + strings.Join(aces, ""), nil
}

func parseACE(data []byte) (string, error) {
	dataLen := len(data)

	if dataLen < 16 {
		return "", fmt.Errorf("invalid ACE: too short, got %d bytes but need at least 16 (4 for header + 4 for access mask + 8 for SID)", dataLen)
	}

	aceType := data[0]
	aceFlags := data[1]
	aceSize := binary.LittleEndian.Uint16(data[2:4])

	// Validate full ACE size matches data provided
	if uint16(dataLen) != aceSize {
		return "", fmt.Errorf("invalid ACE: data length %d doesn't match ACE size %d", dataLen, aceSize)
	}

	accessMask := binary.LittleEndian.Uint32(data[4:8])

	sid, err := parseSID(data[8:])
	if err != nil {
		return "", fmt.Errorf("error parsing ACE SID: %w", err)
	}

	// Get ACE type string
	var aceTypeStr string
	switch aceType {
	case ACCESS_ALLOWED_ACE_TYPE:
		aceTypeStr = "A"
	case ACCESS_DENIED_ACE_TYPE:
		aceTypeStr = "D"
	case SYSTEM_AUDIT_ACE_TYPE:
		aceTypeStr = "AU"
	default:
		aceTypeStr = fmt.Sprintf("0x%02X", aceType)
	}

	// Convert flags to string
	var flagsStr string
	if aceFlags&CONTAINER_INHERIT_ACE != 0 {
		flagsStr += "CI"
	}
	if aceFlags&OBJECT_INHERIT_ACE != 0 {
		flagsStr += "OI"
	}
	if aceFlags&INHERIT_ONLY_ACE != 0 {
		flagsStr += "IO"
	}
	if aceFlags&INHERITED_ACE != 0 {
		flagsStr += "ID"
	}

	// Format access mask, checking for well-known combinations first
	var accessStr string
	if knownAccess, ok := wellKnownAccessMasks[accessMask]; ok {
		accessStr = knownAccess
	} else if accessMask == 0 {
		accessStr = "NO_ACCESS"
	} else {
		// Format with 0x prefix and no leading zeros
		accessStr = fmt.Sprintf("0x%x", accessMask)
	}

	// Use standard Windows SDDL format with placeholder semicolons
	return fmt.Sprintf("(%s;%s;%s;;;%s)", aceTypeStr, flagsStr, accessStr, sid), nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		input := scanner.Text()

		if strings.TrimSpace(input) == "" {
			continue
		}

		data, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error on line %d decoding base64: %v\n", lineNum, err)
			continue
		}

		result, err := ParseSecurityDescriptor(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error on line %d parsing security descriptor: %v\n", lineNum, err)
			continue
		}

		fmt.Printf("%s\n", result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}
}
