//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                                             = windows.NewLazyDLL("advapi32.dll")
	convertSecurityDescriptorToStringSecurityDescriptorW = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	convertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getSecurityInfo                                      = advapi32.NewProc("GetSecurityInfo")
	getSecurityDescriptorLength                          = advapi32.NewProc("GetSecurityDescriptorLength")
	getSecurityDescriptorControl                         = advapi32.NewProc("GetSecurityDescriptorControl")
	makeSelfRelativeSD                                   = advapi32.NewProc("MakeSelfRelativeSD")
	openProcessToken                                     = advapi32.NewProc("OpenProcessToken")
	lookupPrivilegeValueW                                = advapi32.NewProc("LookupPrivilegeValueW")
	adjustTokenPrivileges                                = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	OWNER_SECURITY_INFORMATION = 0x00000001
	GROUP_SECURITY_INFORMATION = 0x00000002
	DACL_SECURITY_INFORMATION  = 0x00000004
	SACL_SECURITY_INFORMATION  = 0x00000008

	SE_SECURITY_NAME        = "SeSecurityPrivilege"
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008

	// Adding missing constants
	READ_CONTROL           = 0x00020000
	ACCESS_SYSTEM_SECURITY = 0x01000000

	// Security descriptor control flags
	SE_SELF_RELATIVE = 0x8000
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

func enableSecurityPrivilege() error {

	var token windows.Token
	currentProcess := windows.CurrentProcess()

	// Get process token
	ret, _, err := openProcessToken.Call(
		uintptr(currentProcess),
		uintptr(TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	// Lookup the privilege value
	var luid LUID
	privName, err := syscall.UTF16PtrFromString(SE_SECURITY_NAME)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %v", err)
	}

	ret, _, err = lookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	// Prepare token privileges
	var tp TOKEN_PRIVILEGES
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = 0x00000002 // SE_PRIVILEGE_ENABLED

	// Adjust token privileges
	ret, _, err = adjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

func getSecurityDescriptorPointerAndInfo(filename string) (uintptr, int, error) {

	// Open the file to get a handle
	pathPtr, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return 0, 0, fmt.Errorf("Error converting filename: %w", err)
	}

	// Check if path is a directory
	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return 0, 0, fmt.Errorf("Error getting file attributes: %w", err)
	}

	var fileFlags uint32 = syscall.FILE_ATTRIBUTE_NORMAL
	if attrs&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		fileFlags = syscall.FILE_FLAG_BACKUP_SEMANTICS
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		READ_CONTROL|ACCESS_SYSTEM_SECURITY,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		fileFlags,
		0,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("Error opening file: %w", err)
	}
	defer syscall.CloseHandle(handle)

	// Get the security descriptor
	var pSD, pOwner, pGroup, pDacl, pSacl uintptr
	secInfo := OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION

	ret, _, err := getSecurityInfo.Call(
		uintptr(handle),
		uintptr(1), // SE_FILE_OBJECT
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&pOwner)),
		uintptr(unsafe.Pointer(&pGroup)),
		uintptr(unsafe.Pointer(&pDacl)),
		uintptr(unsafe.Pointer(&pSacl)),
		uintptr(unsafe.Pointer(&pSD)),
	)

	// If failed, try without SACL
	if ret != 0 {
		fmt.Fprintf(os.Stderr, "Warning: Could not get full security info, trying without SACL...\n")
		secInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		ret, _, err = getSecurityInfo.Call(
			uintptr(handle),
			uintptr(1), // SE_FILE_OBJECT
			uintptr(secInfo),
			uintptr(unsafe.Pointer(&pOwner)),
			uintptr(unsafe.Pointer(&pGroup)),
			uintptr(unsafe.Pointer(&pDacl)),
			0,
			uintptr(unsafe.Pointer(&pSD)),
		)
		if ret != 0 {
			return 0, 0, fmt.Errorf("GetSecurityInfo failed: %w", err)
		}
	}

	return pSD, secInfo, nil
}

// GetFileSDBytes retrieves a file's security descriptor in binary form.
// It uses direct Windows API calls to get the raw SD bytes.
func GetFileSDBytes(filename string) ([]byte, error) {
	// Try to enable security privilege
	err := enableSecurityPrivilege()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not enable security privilege: %v\n", err)
		fmt.Fprintf(os.Stderr, "Will try to continue with reduced privileges...\n")
	}

	pSD, _, err := getSecurityDescriptorPointerAndInfo(filename)
	if err != nil {
		return nil, err
	}

	// Check if the security descriptor is already self-relative
	var control uint16
	var revision uint32
	ret, _, err := getSecurityDescriptorControl.Call(
		pSD,
		uintptr(unsafe.Pointer(&control)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetSecurityDescriptorControl failed: %w", err)
	}

	var finalSD uintptr
	var sdSize uint32

	if control&SE_SELF_RELATIVE == 0 {
		// First acll to get required buffer size
		ret, _, err = makeSelfRelativeSD.Call(
			pSD,
			0,
			uintptr(unsafe.Pointer(&sdSize)),
		)
		if ret == 0 {
			return nil, fmt.Errorf("MakeSelfRelativeSD failed: %v", err)
		}

		// Allocate buffer
		finalSD, err := windows.LocalAlloc(0, sdSize)
		if finalSD == 0 {
			return nil, fmt.Errorf("LocalAlloc failed: %v", err)
		}
		defer windows.LocalFree(windows.Handle(finalSD))

		// Second call to actually convert
		ret, _, err = makeSelfRelativeSD.Call(
			pSD,
			finalSD,
			uintptr(unsafe.Pointer(&sdSize)),
		)
		if ret == 0 {
			return nil, fmt.Errorf("MakeSelfRelativeSD failed (2): %v", err)
		}
	} else {
		finalSD = pSD
		length, _, _ := getSecurityDescriptorLength.Call(pSD)
		sdSize = uint32(length)
	}

	// Copy to byte slice and encode
	sdBytes := make([]byte, sdSize)
	for i := uint32(0); i < sdSize; i++ {
		sdBytes[i] = *(*byte)(unsafe.Pointer(finalSD + uintptr(i)))
	}

	return sdBytes, nil
}

// GetFileSDString retrieves a file's security descriptor as a SDDL string.
// It tries to use the ConvertSecurityDescriptorToStringSecurityDescriptor API
// first for accuracy, but falls back to our SDDL package if that fails.
func GetFileSDString(filename string) (string, error) {

	// Try to enable security privilege
	err := enableSecurityPrivilege()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not enable security privilege: %v\n", err)
		fmt.Fprintf(os.Stderr, "Will try to continue with reduced privileges...\n")
	}

	pSD, secInfo, err := getSecurityDescriptorPointerAndInfo(filename)
	if err != nil {
		return "", err
	}

	// Convert to string format (SDDL)
	var strPtr *uint16
	ret, _, err := convertSecurityDescriptorToStringSecurityDescriptorW.Call(
		pSD,
		uintptr(1),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&strPtr)),
		0,
	)
	if ret == 0 {
		return "", fmt.Errorf("ConvertSecurityDescriptorToString failed: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(strPtr)))

	// Convert UTF16 to string and print SDDL
	sddl := windows.UTF16PtrToString(strPtr)

	return sddl, nil
}

// GetFileSecurityBase64 retrieves a file's security descriptor in base64-encoded format.
func GetFileSecurityBase64(filename string) (string, error) {
	sd, err := GetFileSDBytes(filename)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sd), nil
}
