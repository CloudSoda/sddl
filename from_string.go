package sddl

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseSecurityDescriptorString parses a security descriptor string in SDDL format.
// The format is: "O:owner_sidG:group_sidD:dacl_flagsS:sacl_flags"
// where each component is optional.
//
// Examples:
// - "O:SYG:BAD:(A;;FA;;;SY)"            - Owner: SYSTEM, Group: BUILTIN\Administrators, DACL with full access for SYSTEM
// - "O:SYG:SYD:PAI(A;;FA;;;SY)"         - Protected auto-inherited DACL
// - "O:SYG:SYD:(A;;FA;;;SY)S:(AU;SA;FA;;;SY)" - With both DACL and SACL
func ParseSecurityDescriptorString(s string) (*SecurityDescriptor, error) {
	// Initialize security descriptor with self-relative flag
	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_DEFAULTED, // All components are defaulted unless they are present
	}

	// Empty string is valid - returns a security descriptor with defaults set
	if s == "" {
		return sd, nil
	}

	remaining := s
	var err error

	// Parse each component in order if present
	// The order doesn't technically matter, so, we are going to keep a list of pending components to parse
	// and remove them as we go
	pendingComponents := []string{"O:", "G:", "D:", "S:"}
	removePendingComponent := func(component string) {
		for i, c := range pendingComponents {
			if c == component {
				pendingComponents = append(pendingComponents[:i], pendingComponents[i+1:]...)
				break
			}
		}
	}

	// If there is data, then, at least one component must be present
	if findNextComponent(remaining, pendingComponents...) == -1 {
		return nil, fmt.Errorf("no components found in security descriptor")
	}

	// Parse each component regardless of their order, as long as there are remaining characters and pending components
	for len(pendingComponents) > 0 && len(remaining) > 0 {
		switch {
		case strings.HasPrefix(remaining, "O:"):
			// remove O: prefix
			remaining = remaining[2:]
			removePendingComponent("O:")
			sd.OwnerSID, remaining, err = parseSIDComponent(remaining, pendingComponents...)
			if err != nil {
				return nil, fmt.Errorf("error parsing owner SID: %w", err)
			}
			sd.Control ^= SE_OWNER_DEFAULTED

		case strings.HasPrefix(remaining, "G:"):
			// remove G: prefix
			remaining = remaining[2:]
			removePendingComponent("G:")
			sd.GroupSID, remaining, err = parseSIDComponent(remaining, pendingComponents...)
			if err != nil {
				return nil, fmt.Errorf("error parsing group SID: %w", err)
			}
			sd.Control ^= SE_GROUP_DEFAULTED

		case strings.HasPrefix(remaining, "D:"):
			removePendingComponent("D:")
			sd.DACL, remaining, err = parseACLComponent(remaining, pendingComponents...)
			if err != nil {
				return nil, fmt.Errorf("error parsing DACL: %w", err)
			}
			sd.Control ^= SE_DACL_DEFAULTED
			sd.Control |= SE_DACL_PRESENT

			// Update control flags based on DACL flags
			if sd.DACL.Control&SE_DACL_PROTECTED != 0 {
				sd.Control |= SE_DACL_PROTECTED
			}
			if sd.DACL.Control&SE_DACL_AUTO_INHERITED != 0 {
				sd.Control |= SE_DACL_AUTO_INHERITED
			}
			if sd.DACL.Control&SE_DACL_AUTO_INHERIT_RE != 0 {
				sd.Control |= SE_DACL_AUTO_INHERIT_RE
			}

		case strings.HasPrefix(remaining, "S:"):
			removePendingComponent("S:")
			sd.SACL, remaining, err = parseACLComponent(remaining, pendingComponents...)
			if err != nil {
				return nil, fmt.Errorf("error parsing SACL: %w", err)
			}
			sd.Control ^= SE_SACL_DEFAULTED
			sd.Control |= SE_SACL_PRESENT

			// Update control flags based on SACL flags
			if sd.SACL.Control&SE_SACL_PROTECTED != 0 {
				sd.Control |= SE_SACL_PROTECTED
			}
			if sd.SACL.Control&SE_SACL_AUTO_INHERITED != 0 {
				sd.Control |= SE_SACL_AUTO_INHERITED
			}
			if sd.SACL.Control&SE_SACL_AUTO_INHERIT_RE != 0 {
				sd.Control |= SE_SACL_AUTO_INHERIT_RE
			}
		}
	}

	// If there's anything left unparsed, it's an error
	if remaining != "" {
		return nil, fmt.Errorf("unexpected content after parsing: %s", remaining)
	}

	// Adjust ACL's control flags once they are fully computed
	if sd.DACL != nil {
		sd.DACL.Control = sd.Control
	}
	if sd.SACL != nil {
		sd.SACL.Control = sd.Control
	}

	return sd, nil
}

func parseSIDComponent(s string, nextMarkers ...string) (sid *SID, remaining string, err error) {
	// Find the next component marker (G:, D:, or S:)
	sidEnd := findNextComponent(s, nextMarkers...)
	if sidEnd == -1 {
		sidEnd = len(s)
	}

	// Parse the SID string
	sid, err = parseSIDString(s[:sidEnd])
	if err != nil {
		return nil, "", fmt.Errorf("invalid SID: %w", err)
	}

	return sid, s[sidEnd:], nil
}

func parseACLComponent(s string, nextMarkers ...string) (acl *ACL, remaining string, err error) {
	// Find the next marker (if any)
	aclEnd := len(s)
	if len(nextMarkers) > 0 {
		nextMarkerIndex := findNextComponent(s, nextMarkers...)
		if nextMarkerIndex != -1 {
			aclEnd = nextMarkerIndex
		}
	}

	// Parse the ACL string
	acl, err = parseACLString(s[:aclEnd])
	if err != nil {
		return nil, "", fmt.Errorf("invalid ACL: %w", err)
	}

	return acl, s[aclEnd:], nil
}

// findNextComponent looks for the next component marker given in arguments
// Returns the index of the next component or -1 if none found
func findNextComponent(s string, markers ...string) int {
	minIndex := -1
	for _, marker := range markers {
		if idx := strings.Index(s, marker); idx != -1 {
			if minIndex == -1 || idx < minIndex {
				minIndex = idx
			}
		}
	}

	return minIndex
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
// The valid types are:
// - A (ACCESS_ALLOWED_ACE_TYPE): allows access to the object
// - D (ACCESS_DENIED_ACE_TYPE): denies access to the object
// - AU (SYSTEM_AUDIT_ACE_TYPE): specifies a system audit ACE
// - AL (SYSTEM_ALARM_ACE_TYPE): specifies a system alarm ACE
// - OA (ACCESS_ALLOWED_OBJECT_ACE_TYPE): specifies an object-specific access ACE
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
