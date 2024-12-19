# wsec-parse (Windows Security Descriptor Parser)

This project provides functionality to parse Windows Security Descriptors from their binary format into their string representation (SDDL format). It can be used either as a standalone command-line tool or as a library.

## Standalone Program Usage

When compiled as a standalone program, it:
1. Reads base64-encoded binary security descriptor data from stdin, one descriptor per line
2. Converts each descriptor to its SDDL string representation
3. Outputs the SDDL strings to stdout
4. Reports any errors to stderr while continuing to process remaining lines

### Example Usage
```bash
# Process a single security descriptor
echo "base64_encoded_data" | ./security-descriptor-parser

# Process multiple descriptors from a file
cat descriptors.txt | ./security-descriptor-parser
```

### Input Format
- Each line should contain a single base64-encoded security descriptor
- Empty lines are ignored
- Processing continues even if some lines fail to parse

### Output Format
- Successfully parsed descriptors are printed to stdout in SDDL format
- Each output line follows Windows SDDL syntax: `O:owner_sidG:group_sidD:dacl_flags(ace_list)`
- Parsing errors are printed to stderr with line numbers

## Library Usage

The main functionality is provided through the `ParseSecurityDescriptor` function:

```go
func ParseSecurityDescriptor(data []byte) (string, error)
```

### Parameters
- `data []byte`: Binary security descriptor in relative format (contiguous memory with offsets)

### Returns
- `string`: SDDL representation of the security descriptor
- `error`: Any error encountered during parsing

### Example
```go
import "your/package/path"

func ProcessDescriptor(binaryData []byte) {
    sddl, err := ParseSecurityDescriptor(binaryData)
    if err != nil {
        // Handle error
        return
    }
    // Use SDDL string...
}
```

### Features
- Parses owner and group SIDs
- Handles DACL and SACL
- Supports inheritance flags
- Translates well-known SIDs to their aliases (e.g., "SY" for SYSTEM)
- Translates common access masks to symbolic form (e.g., "FA" for Full Access)
- Follows Windows SDDL format specification
- Cross-platform: Does not depend on Windows API (`golang.org/x/sys/windows`), making it usable on any operating system
- Pure Go implementation for maximum portability

### Limitations
- Only handles relative format security descriptors
- Does not handle object-specific ACEs (used in Active Directory)

## SDDL Format Details

The output follows the Windows Security Descriptor String Format (SDDL):
- Owner: `O:sid`
- Group: `G:sid`
- DACL: `D:dacl_flags(ace_list)`
- SACL: `S:sacl_flags(ace_list)`

Each ACE in the ace_list follows the format:
```
(ace_type;ace_flags;rights;;;account_sid)
```

### Common Values
- ACE Types: "A" (Allow), "D" (Deny), "AU" (Audit)
- ACE Flags: "CI" (Container Inherit), "OI" (Object Inherit), "ID" (Inherited)
- Rights: "FA" (Full Access), "RA" (Read/Execute), etc.
- Well-known SIDs: "SY" (SYSTEM), "BA" (Administrators), etc.

## Error Handling

The parser provides detailed error messages for various failure scenarios:
- Invalid security descriptor length
- Invalid SID format
- Invalid ACL format
- Invalid ACE format
- Base64 decoding errors (in standalone mode)

Errors include context about where in the parsing process they occurred to aid in debugging.
