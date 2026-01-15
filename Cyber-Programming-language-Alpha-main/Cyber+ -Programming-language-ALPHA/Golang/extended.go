package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ---------------- VERSION ----------------
const CyberPlusVersion = "1.0.0-alpha"

// ---------------- CLI HANDLER ----------------
func handleCLI() bool {
	args := os.Args

	// No CLI args → normal REPL
	if len(args) == 1 {
		return false
	}

	switch args[1] {

	case "--version":
		fmt.Println("Cyber+ version", CyberPlusVersion)
		return true

	case "run":
		if len(args) < 3 {
			fmt.Println("Usage: cyberplus run <file.cbp>")
			return true
		}
		runCBPFile(args[2])
		return true

	case "build":
		if len(args) < 4 || args[2] != "exe" {
			fmt.Println("Usage: cyberplus build exe <file.cbp>")
			return true
		}
		buildExeWrapper(args[3])
		return true

	default:
		fmt.Println("Unknown command:", args[1])
		return true
	}
}

// ---------------- RUN .CBP FILE ----------------
func runCBPFile(filename string) {
	if !strings.HasSuffix(filename, ".cbp") {
		fmt.Println("Error: Only .cbp files are supported")
		return
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return
	}

	engineActive = true
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		executed := false
		for _, r := range getRules() {
			if m := r.re.FindStringSubmatch(line); len(m) > 0 {
				r.fn(m)
				executed = true
				break
			}
		}

		if !executed {
			fmt.Println("Unknown Cyber+ command:", line)
		}
	}
}

// ---------------- BUILD WINDOWS EXECUTABLE ----------------
func buildExeWrapper(script string) {
	if !strings.HasSuffix(script, ".cbp") {
		fmt.Println("Error: Only .cbp files are supported")
		return
	}

	output := strings.TrimSuffix(filepath.Base(script), ".cbp") + ".exe"

	// Create temporary Go wrapper
	wrapper := fmt.Sprintf(`package main

import "os"

func main() {
	args := []string{"run", "%s"}
	os.Args = append([]string{os.Args[0]}, args...)
	main() // call Cyber+ main()
}
`, script)

	tmpFile := "wrapper.go"
	err := os.WriteFile(tmpFile, []byte(wrapper), 0644)
	if err != nil {
		fmt.Println("Failed to create wrapper:", err)
		return
	}

	// Build the wrapper
	cmd := exec.Command("go", "build", "-o", output, tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Building Windows executable:", output)
	err = cmd.Run()
	if err != nil {
		fmt.Println("Build failed:", err)
		os.Remove(tmpFile)
		return
	}

	os.Remove(tmpFile)
	fmt.Println("Build successful:", output)
}
