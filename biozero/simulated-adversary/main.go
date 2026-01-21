// SPDX-License-Identifier: AGPL-3.0-only
// Simulated adversary: generates synthetic FASTQ-like files and invokes the
// uploader-cli to create background traffic for the MVP services.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

/// main generates synthetic FASTQ-like files and invokes uploader-cli.
///
/// Brief description of what the function does.
/// - Produces sample payloads and drives the upload API to simulate traffic.
///
/// Parameters:
///   None (reads flags for configuration).
///
/// Returns no value; exits with non-zero status on fatal validation errors.
///
/// Throws [FatalInputError] when configuration flags are invalid.
///
/// Example: `go run ./main.go --count 5 --out-dir ./simulated`
func main() {
	count := flag.Int("count", 5, "number of uploads to simulate")
	outputDir := flag.String("out-dir", "./simulated", "where to write generated files")
	uploader := flag.String("uploader", "../services/uploader-cli", "path to uploader-cli dir")
	flag.Parse()

	// Validate count to avoid empty or negative loops.
	if *count <= 0 {
		fmt.Fprintln(os.Stderr, "count must be greater than 0")
		// Return after writing the error to avoid useless work.
		os.Exit(1)
	}
	// Validate uploader path to ensure go run will succeed.
	if stat, err := os.Stat(*uploader); err != nil || !stat.IsDir() {
		fmt.Fprintln(os.Stderr, "uploader path is invalid")
		// Return after writing the error to avoid invoking an invalid path.
		os.Exit(1)
	}
	// Create the output directory before generating files.
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir error: %v\n", err)
		// Return to avoid writing into a non-existent directory.
		os.Exit(1)
	}

	// Seed randomness for varied sample content and names.
	rand.Seed(time.Now().UnixNano())
	// Loop through each simulated sample to generate and upload data.
	for i := 0; i < *count; i++ {
		name := randomName(i)
		path := filepath.Join(*outputDir, name)
		// Write random bytes to simulate a FASTQ-like payload.
		if err := os.WriteFile(path, randomBytes(1024+rand.Intn(2048)), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			// Continue to the next sample to keep the simulation running.
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		cmd := exec.CommandContext(ctx, "go", "run", "./main.go", "--file", path, "--client-id", "simulator")
		cmd.Dir = *uploader
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// Run uploader-cli; log errors but keep the simulation progressing.
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "uploader failed: %v\n", err)
		}
		// Cancel the context to release resources after execution.
		cancel()
	}
}

/// randomName returns a filename that alternates between benign and suspicious names.
///
/// Brief description of what the function does.
/// - Generates alternating names to trigger filename-based detection logic.
///
/// Parameters:
///   index - Zero-based index of the generated sample.
///
/// Returns a FASTQ-style filename.
///
/// Throws [None] - pure string formatting.
///
/// Example: `name := randomName(3)`
func randomName(index int) string {
	// Use alternating naming to exercise detection rules.
	if index%2 == 0 {
		// Return a benign sample name for even indices.
		return fmt.Sprintf("sample_%d.fastq", index)
	}
	// Return a suspicious sample name for odd indices.
	return fmt.Sprintf("malware_sample_%d.fastq", index)
}

/// randomBytes generates pseudo-random bytes for synthetic payloads.
///
/// Brief description of what the function does.
/// - Produces random data to simulate variable content sizes.
///
/// Parameters:
///   size - Desired number of bytes.
///
/// Returns a byte slice of length size.
///
/// Throws [None] - uses math/rand for simulation only.
///
/// Example: `data := randomBytes(2048)`
func randomBytes(size int) []byte {
	buf := make([]byte, size)
	// Fill the buffer with random values for simulation realism.
	for i := range buf {
		buf[i] = byte(rand.Intn(256))
	}
	// Return the generated buffer.
	return buf
}
