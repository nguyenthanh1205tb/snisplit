// Command genicon writes the logo images used for the Windows executable
// (winres/) and the README (docs/logo.png). Run from the repository root:
//
//	go generate ./...
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/nguyenthanh1205tb/snisplit/internal/logo"
)

func main() {
	write := func(path string, data []byte) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", path)
	}
	for _, n := range logo.IconSizes {
		write(fmt.Sprintf("winres/icon-%d.png", n), logo.PNG(n, logo.Running, n <= 24))
	}
	write("docs/logo.png", logo.PNG(256, logo.Running, false))
}
