// policy-bundle signs reviewed policy releases offline. Private keys never need
// to be installed on request-serving proxy nodes.
package main

import (
	"ads-httpproxy/internal/controlplane"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	generate := flag.Bool("generate-key", false, "Create a private key file (exclusive) and print its public key")
	keyPath := flag.String("key", "", "Private key file (base64 Ed25519)")
	id := flag.String("key-id", "", "Trusted signing key identifier")
	input := flag.String("input", "", "Reviewed release JSON to sign")
	flag.Parse()
	if *keyPath == "" {
		return fmt.Errorf("-key is required")
	}
	if *generate {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	}
	if *id == "" || *input == "" {
		return fmt.Errorf("-key-id and -input are required to sign")
	}
	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil {
		return err
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("release too large")
	}
	var release controlplane.Release
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&release); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	envelope, err := controlplane.Sign(*id, key, release)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(envelope)
}
