// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
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

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("mkdir error: %v\n", err)
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < *count; i++ {
		name := randomName(i)
		path := filepath.Join(*outputDir, name)
		if err := os.WriteFile(path, randomBytes(1024+rand.Intn(2048)), 0644); err != nil {
			fmt.Printf("write error: %v\n", err)
			continue
		}

		cmd := exec.Command("go", "run", "./main.go", "--file", path, "--client-id", "simulator")
		cmd.Dir = *uploader
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
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
