package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudsoda/sddl"
)

type config struct {
	inputFormat  string
	outputFormat string
	fileMode     bool
	debug        bool
}

func main() {
	cfg := parseFlags()

	if err := processInput(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	cfg := config{}

	flag.StringVar(&cfg.inputFormat, "i", "binary", "Input format: 'binary' (base64 encoded) or 'string'")
	flag.StringVar(&cfg.outputFormat, "o", "string", "Output format: 'binary' (base64 encoded) or 'string'")
	flag.BoolVar(&cfg.fileMode, "file", false, "Process input as filenames and read their security descriptors using native Windows API calls")
	flag.BoolVar(&cfg.debug, "debug", false, "Enable debugging output (applies only if -o string is set)")
	flag.Parse()

	// Validate input format
	cfg.inputFormat = strings.ToLower(cfg.inputFormat)
	if cfg.inputFormat != "binary" && cfg.inputFormat != "string" {
		fmt.Fprintf(os.Stderr, "invalid input format: %s (must be 'binary' or 'string')\n", cfg.inputFormat)
		flag.Usage()
		os.Exit(1)
	}

	// Validate output format
	cfg.outputFormat = strings.ToLower(cfg.outputFormat)
	if cfg.outputFormat != "binary" && cfg.outputFormat != "string" {
		fmt.Fprintf(os.Stderr, "invalid output format: %s (must be 'binary' or 'string')\n", cfg.outputFormat)
		flag.Usage()
		os.Exit(1)
	}

	// Input format is ignored in file mode
	if cfg.fileMode && cfg.inputFormat != "binary" {
		fmt.Fprintln(os.Stderr, "warning: input format is ignored in file mode")
	}

	return cfg
}

func processInput(cfg config) error {
	scanner := bufio.NewScanner(os.Stdin)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		input := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(input) == "" {
			continue
		}

		if cfg.fileMode {
			// Process input as filename
			var output string
			var err error
			if cfg.outputFormat == "binary" {
				output, err = GetFileSecurityBase64(input)
			} else {
				output, err = GetFileSDString(input)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error processing file %q: %v\n", lineNum, input, err)
				continue
			}
			fmt.Println(output)
			continue
		}

		// Process security descriptor input
		var sd *sddl.SecurityDescriptor
		var err error

		// Parse input based on format
		switch cfg.inputFormat {
		case "binary":
			data, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error decoding base64: %v\n", lineNum, err)
				continue
			}
			sd, err = sddl.FromBinary(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error parsing security descriptor: %v\n", lineNum, err)
				continue
			}

		case "string":
			sd, err = sddl.FromString(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error parsing security descriptor string: %v\n", lineNum, err)
				continue
			}
		}

		// Generate output based on format
		switch cfg.outputFormat {
		case "binary":
			fmt.Println(base64.StdEncoding.EncodeToString(sd.Binary()))
		case "string":
			if cfg.debug {
				fmt.Println(sd.StringIndent(0))
			} else {
				fmt.Println(sd.String())
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	return nil
}
