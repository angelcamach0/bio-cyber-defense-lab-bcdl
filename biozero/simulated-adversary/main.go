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

func main() {
	count := flag.Int("count", 5, "number of uploads to simulate")
	outputDir := flag.String("out-dir", "./simulated", "where to write generated files")
	uploader := flag.String("uploader", "../services/uploader-cli", "path to uploader-cli dir")
	flag.Parse()

	if *count <= 0 {
		fmt.Fprintln(os.Stderr, "count must be greater than 0")
		os.Exit(1)
	}
	if stat, err := os.Stat(*uploader); err != nil || !stat.IsDir() {
		fmt.Fprintln(os.Stderr, "uploader path is invalid")
		os.Exit(1)
	}
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir error: %v\n", err)
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < *count; i++ {
		name := randomName(i)
		path := filepath.Join(*outputDir, name)
		if err := os.WriteFile(path, randomBytes(1024+rand.Intn(2048)), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		cmd := exec.CommandContext(ctx, "go", "run", "./main.go", "--file", path, "--client-id", "simulator")
		cmd.Dir = *uploader
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "uploader failed: %v\n", err)
		}
		cancel()
	}
}

func randomName(index int) string {
	if index%2 == 0 {
		return fmt.Sprintf("sample_%d.fastq", index)
	}
	return fmt.Sprintf("malware_sample_%d.fastq", index)
}

func randomBytes(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(rand.Intn(256))
	}
	return buf
}
