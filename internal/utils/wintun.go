package utils

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// EnsureWintun checks if wintun.dll exists in the executable's directory.
// If it does not, it downloads the official Wintun distribution and extracts the correct architecture DLL.
func EnsureWintun() error {
	dllName := "wintun.dll"
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	dllPath := filepath.Join(exeDir, dllName)

	if _, err := os.Stat(dllPath); err == nil {
		// wintun.dll already exists
		return nil
	}

	fmt.Println("Downloading wintun.dll, this may take a moment...")

	url := "https://www.wintun.net/builds/wintun-0.14.1.zip"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download wintun: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download wintun: HTTP %d", resp.StatusCode)
	}

	// Read zip file into memory
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read wintun zip: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to parse wintun zip: %w", err)
	}

	arch := runtime.GOARCH
	var targetArch string
	switch arch {
	case "amd64":
		targetArch = "amd64"
	case "386":
		targetArch = "x86"
	case "arm":
		targetArch = "arm"
	case "arm64":
		targetArch = "arm64"
	default:
		return fmt.Errorf("unsupported architecture for wintun: %s", arch)
	}

	targetFileInZip := fmt.Sprintf("wintun/bin/%s/wintun.dll", targetArch)
	var winTunFile *zip.File
	for _, f := range zipReader.File {
		if f.Name == targetFileInZip {
			winTunFile = f
			break
		}
	}

	if winTunFile == nil {
		return fmt.Errorf("could not find %s in downloaded zip", targetFileInZip)
	}

	// Extract wintun.dll
	rc, err := winTunFile.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outFile, err := os.Create(dllPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", dllPath, err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", dllPath, err)
	}

	fmt.Println("wintun.dll installed successfully.")
	return nil
}
