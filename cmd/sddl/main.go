package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/cloudsoda/sddl"
)

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

		sdl, err := sddl.FromBinary(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error on line %d parsing security descriptor: %v\n", lineNum, err)
			continue
		}

		fmt.Printf("%v\n", sdl)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}
}
