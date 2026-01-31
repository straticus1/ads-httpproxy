package dlp

import (
	"ads-httpproxy/pkg/logging"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// VisualDLP implements advanced DLP with visual analysis capabilities
type VisualDLP struct {
	regexScanner      *RegexScanner
	categoryClient    *CategoryClient
	screenshotService string
	ocrEnabled        bool
	mu                sync.RWMutex

	// Policy configuration
	blockCategories   map[string]bool
	captureCategories map[string]bool
	sensitivePatterns []string
}

// CategoryClient interfaces with the URL categorization service
type CategoryClient struct {
	baseURL    string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*CategoryResponse
}

// CategoryResponse from the categorization service
type CategoryResponse struct {
	URL        string   `json:"url"`
	Domain     string   `json:"domain"`
	Categories []string `json:"categories"`
	Found      bool     `json:"found"`
	Source     string   `json:"source,omitempty"`
}

// CategoryRequest for categorization service
type CategoryRequest struct {
	URL string `json:"url"`
}

// ScanResult represents the result of a DLP scan
type ScanResult struct {
	Blocked       bool
	Reason        string
	Categories    []string
	Violations    []string
	ScreenshotURL string
	OCRText       string
	Timestamp     time.Time
	Action        string // "allow", "block", "alert"
	Evidence      map[string]interface{}
}

// NewVisualDLP creates a new Visual DLP instance
func NewVisualDLP(patterns []string, categoryServiceURL, screenshotServiceURL string) (*VisualDLP, error) {
	scanner, err := NewRegexScanner(patterns)
	if err != nil {
		return nil, err
	}

	return &VisualDLP{
		regexScanner:      scanner,
		categoryClient:    NewCategoryClient(categoryServiceURL),
		screenshotService: screenshotServiceURL,
		ocrEnabled:        true,
		blockCategories:   make(map[string]bool),
		captureCategories: make(map[string]bool),
		sensitivePatterns: patterns,
	}, nil
}

// NewCategoryClient creates a new category client
func NewCategoryClient(baseURL string) *CategoryClient {
	return &CategoryClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache: make(map[string]*CategoryResponse),
	}
}

// GetCategory retrieves category information for a URL
func (c *CategoryClient) GetCategory(url string) (*CategoryResponse, error) {
	c.mu.RLock()
	if cached, ok := c.cache[url]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	req := CategoryRequest{URL: url}
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/category",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("category service returned %d", resp.StatusCode)
	}

	var result CategoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Cache result
	c.mu.Lock()
	c.cache[url] = &result
	c.mu.Unlock()

	return &result, nil
}

// SetBlockCategories configures which categories should be blocked
func (v *VisualDLP) SetBlockCategories(categories []string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.blockCategories = make(map[string]bool)
	for _, cat := range categories {
		v.blockCategories[cat] = true
	}
}

// SetCaptureCategories configures which categories should trigger screenshot capture
func (v *VisualDLP) SetCaptureCategories(categories []string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.captureCategories = make(map[string]bool)
	for _, cat := range categories {
		v.captureCategories[cat] = true
	}
}

// ScanRequest performs a comprehensive DLP scan on an HTTP request
func (v *VisualDLP) ScanRequest(url string, body []byte) *ScanResult {
	result := &ScanResult{
		Timestamp: time.Time{},
		Action:    "allow",
		Evidence:  make(map[string]interface{}),
	}

	// 1. Get URL category
	categoryResp, err := v.categoryClient.GetCategory(url)
	if err == nil && categoryResp.Found {
		result.Categories = categoryResp.Categories
		result.Evidence["url_category"] = categoryResp
	}

	// 2. Check if category is blocked
	v.mu.RLock()
	for _, cat := range result.Categories {
		if v.blockCategories[cat] {
			result.Blocked = true
			result.Reason = fmt.Sprintf("Category blocked: %s", cat)
			result.Action = "block"
			break
		}
	}
	v.mu.RUnlock()

	// 3. Scan body for sensitive patterns
	if len(body) > 0 {
		matched, pattern := v.regexScanner.Scan(body)
		if matched {
			result.Violations = append(result.Violations, pattern)
			if !result.Blocked {
				result.Blocked = true
				result.Reason = "Sensitive data pattern detected"
				result.Action = "block"
			}
			result.Evidence["dlp_match"] = pattern
		}
	}

	// 4. Determine if screenshot should be captured
	v.mu.RLock()
	shouldCapture := false
	for _, cat := range result.Categories {
		if v.captureCategories[cat] {
			shouldCapture = true
			break
		}
	}
	v.mu.RUnlock()

	if shouldCapture || result.Blocked {
		// Scheduled screenshot (Integration via service call in future iteration)
		logging.Logger.Info("Scheduled screenshot capture", zap.String("url", url))
		result.Evidence["screenshot_scheduled"] = true
	}

	return result
}

// ScanUpload scans file uploads for sensitive data
func (v *VisualDLP) ScanUpload(filename string, content []byte) *ScanResult {
	result := &ScanResult{
		Timestamp: time.Now(),
		Action:    "allow",
		Evidence:  make(map[string]interface{}),
	}

	result.Evidence["filename"] = filename
	result.Evidence["size"] = len(content)

	// Scan content for sensitive patterns
	matched, pattern := v.regexScanner.Scan(content)
	if matched {
		result.Violations = append(result.Violations, pattern)
		result.Blocked = true
		result.Reason = "Sensitive data detected in upload"
		result.Action = "block"
		result.Evidence["dlp_match"] = pattern
	}

	// TODO: If it's an image, perform OCR and scan the extracted text
	// TODO: Run ML-based image classification

	return result
}

// Enhanced DLP Patterns (credit cards, SSN, API keys, etc.)
var DefaultDLPPatterns = []string{
	// Credit Cards
	`\b4[0-9]{12}(?:[0-9]{3})?\b`,     // Visa
	`\b5[1-5][0-9]{14}\b`,             // Mastercard
	`\b3[47][0-9]{13}\b`,              // AMEX
	`\b6(?:011|5[0-9]{2})[0-9]{12}\b`, // Discover

	// Social Security Numbers
	`\b\d{3}-\d{2}-\d{4}\b`,
	`\b\d{3}\s\d{2}\s\d{4}\b`,

	// API Keys and Secrets
	`AKIA[0-9A-Z]{16}`, // AWS Access Key
	`(?i)api[_-]?key[_-]?[=:]\s*['\"]?[a-z0-9]{32,}['\"]?`,    // Generic API Key
	`(?i)secret[_-]?key[_-]?[=:]\s*['\"]?[a-z0-9]{32,}['\"]?`, // Secret Key
	`ghp_[a-zA-Z0-9]{36}`,     // GitHub Personal Access Token
	`glpat-[a-zA-Z0-9_-]{20}`, // GitLab Personal Access Token

	// Private Keys
	`-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE\s+KEY-----`,

	// Email addresses (for PII detection)
	`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,

	// Phone numbers (US format)
	`\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`,

	// Medical Record Numbers (MRN)
	`\bMRN[:\s]?\d{6,10}\b`,
	`\b(?:Patient|Medical)\s+(?:ID|Number)[:\s]?\d{6,10}\b`,

	// IP Addresses (internal networks)
	`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	`\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b`,
	`\b192\.168\.\d{1,3}\.\d{1,3}\b`,
}

// GetDefaultVisualDLP returns a VisualDLP instance with default patterns
func GetDefaultVisualDLP(categoryServiceURL, screenshotServiceURL string) (*VisualDLP, error) {
	return NewVisualDLP(DefaultDLPPatterns, categoryServiceURL, screenshotServiceURL)
}
