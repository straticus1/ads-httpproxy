package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"ads-httpproxy/internal/config"

	"go.uber.org/zap"
)

// ads-admin CLI tool

func main() {
	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := validateCmd.String("config", "config.yaml", "Path to configuration file")

	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)
	apiAddr := statsCmd.String("api", "http://localhost:9090", "API Address")

	reloadCmd := flag.NewFlagSet("reload", flag.ExitOnError)
	reloadApiAddr := reloadCmd.String("api", "http://localhost:9090", "API Address")
	reloadSecret := reloadCmd.String("secret", "changeme", "API Secret")

	if len(os.Args) < 2 {
		fmt.Println("Usage: ads-admin <command> [args]")
		fmt.Println("Commands: validate, stats, reload")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "validate":
		validateCmd.Parse(os.Args[2:])
		err := validateConfig(*configPath)
		if err != nil {
			fmt.Printf("❌ Configuration Invalid: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration Valid")

	case "stats":
		statsCmd.Parse(os.Args[2:])
		url := fmt.Sprintf("%s/metrics", *apiAddr)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("❌ Failed to fetch stats: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("❌ API returned status: %d\n", resp.StatusCode)
			os.Exit(1)
		}

		fmt.Println("YOUR PROXY STATS:")
		io.Copy(os.Stdout, resp.Body)

	case "reload":
		reloadCmd.Parse(os.Args[2:])
		url := fmt.Sprintf("%s/reload", *reloadApiAddr)
		req, _ := http.NewRequest("POST", url, nil)
		// Using the reloadSecret that was previously declared but unused
		req.Header.Set("Authorization", "Bearer "+*reloadSecret)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ Failed to trigger reload: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println("✅ Reload triggered successfully.")
		} else {
			fmt.Printf("❌ Reload failed with status: %d\n", resp.StatusCode)
			io.Copy(os.Stdout, resp.Body)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func validateConfig(path string) error {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Just try to load it
	_, err := config.Load(path)
	return err
}
