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
			data, err := sd.Binary()
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error converting to binary: %v\n", lineNum, err)
				continue
			}
			fmt.Println(base64.StdEncoding.EncodeToString(data))

		case "string":
			str, err := sd.String()
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d: error converting to string: %v\n", lineNum, err)
				continue
			}
			fmt.Println(str)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	return nil
}
