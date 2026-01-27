package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"ads-httpproxy/internal/api"
)

func main() {
	addr := flag.String("addr", "http://localhost:9090", "API Server Address")
	secret := flag.String("secret", "changeme", "API Secret")
	cmd := flag.String("cmd", "status", "Command: status, config")
	flag.Parse()

	client := &http.Client{}

	path := "/v1/" + *cmd
	url := *addr + path
	ks := *secret

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}

	ts := time.Now().Format(time.RFC3339)
	payload := "GET" + path + ts
	sig := api.ComputeSignature(ks, payload)

	req.Header.Set(api.HeaderTimestamp, ts)
	req.Header.Set(api.HeaderSignature, sig)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response (%s):\n%s\n", resp.Status, string(body))
}
