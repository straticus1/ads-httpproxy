package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// Client represents an ICAP client implementing RFC 3507.
type Client struct {
	ServerURL    string
	Timeout      time.Duration
	MaxRetries   int
	PreviewSize  int // Preview bytes for ICAP
	AllowOptions bool
	mu           sync.RWMutex
	connPool     chan net.Conn
	poolSize     int
	options      *OptionsResponse
}

// OptionsResponse represents ICAP OPTIONS response.
type OptionsResponse struct {
	Methods        []string
	PreviewSize    int
	AllowTransfer  []string
	MaxConnections int
	TTL            int
	ServiceID      string
	ISTag          string
	OptExtensions  map[string]string
}

// NewClient creates a new ICAP client with connection pooling.
func NewClient(serverURL string) *Client {
	c := &Client{
		ServerURL:    serverURL,
		Timeout:      30 * time.Second,
		MaxRetries:   2,
		PreviewSize:  4096,
		AllowOptions: true,
		poolSize:     10,
		connPool:     make(chan net.Conn, 10),
	}

	// Perform OPTIONS request to discover server capabilities
	if c.AllowOptions {
		if err := c.fetchOptions(); err != nil {
			logging.Logger.Warn("ICAP OPTIONS failed, using defaults", zap.Error(err))
		}
	}

	return c
}

// getConn retrieves a connection from the pool or creates a new one.
func (c *Client) getConn() (net.Conn, error) {
	select {
	case conn := <-c.connPool:
		// Test if connection is still alive
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		one := make([]byte, 1)
		_, err := conn.Read(one)
		conn.SetReadDeadline(time.Time{}) // Clear deadline
		if err == nil {
			// Connection is alive and has data (shouldn't happen)
			return conn, nil
		}
		// Connection dead or no data, create new one
		conn.Close()
	default:
	}

	// Create new connection
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ICAP URL: %w", err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":1344" // Default ICAP port
	}

	conn, err := net.DialTimeout("tcp", host, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ICAP server: %w", err)
	}

	return conn, nil
}

// putConn returns a connection to the pool.
func (c *Client) putConn(conn net.Conn) {
	if conn == nil {
		return
	}

	select {
	case c.connPool <- conn:
		// Successfully returned to pool
	default:
		// Pool full, close connection
		conn.Close()
	}
}

// fetchOptions performs ICAP OPTIONS request.
func (c *Client) fetchOptions() error {
	conn, err := c.getConn()
	if err != nil {
		return err
	}
	defer c.putConn(conn)

	u, _ := url.Parse(c.ServerURL)
	optionsReq := fmt.Sprintf("OPTIONS %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: ads-httpproxy/1.0\r\nEncapsulated: null-body=0\r\n\r\n",
		u.Path, u.Host)

	conn.SetDeadline(time.Now().Add(c.Timeout))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte(optionsReq)); err != nil {
		return fmt.Errorf("failed to send OPTIONS: %w", err)
	}

	reader := bufio.NewReader(conn)
	opts, err := parseOptionsResponse(reader)
	if err != nil {
		return fmt.Errorf("failed to parse OPTIONS: %w", err)
	}

	c.mu.Lock()
	c.options = opts
	if opts.PreviewSize > 0 {
		c.PreviewSize = opts.PreviewSize
	}
	c.mu.Unlock()

	logging.Logger.Info("ICAP OPTIONS received",
		zap.String("service_id", opts.ServiceID),
		zap.Strings("methods", opts.Methods),
		zap.Int("preview_size", opts.PreviewSize))

	return nil
}

// parseOptionsResponse parses ICAP OPTIONS response.
func parseOptionsResponse(reader *bufio.Reader) (*OptionsResponse, error) {
	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(statusLine, "ICAP/1.0 200") {
		return nil, fmt.Errorf("OPTIONS failed: %s", statusLine)
	}

	opts := &OptionsResponse{
		OptExtensions: make(map[string]string),
	}

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Methods":
			opts.Methods = strings.Split(value, ",")
			for i := range opts.Methods {
				opts.Methods[i] = strings.TrimSpace(opts.Methods[i])
			}
		case "Preview":
			opts.PreviewSize, _ = strconv.Atoi(value)
		case "Allow":
			opts.AllowTransfer = strings.Split(value, ",")
		case "Max-Connections":
			opts.MaxConnections, _ = strconv.Atoi(value)
		case "Options-TTL":
			opts.TTL, _ = strconv.Atoi(value)
		case "Service-ID":
			opts.ServiceID = value
		case "ISTag":
			opts.ISTag = value
		default:
			opts.OptExtensions[key] = value
		}
	}

	return opts, nil
}

// ReqMod performs an ICAP REQMOD request (modify HTTP request).
func (c *Client) ReqMod(req *http.Request) (*http.Request, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	u, _ := url.Parse(c.ServerURL)

	// Serialize HTTP request
	var httpReqBuf bytes.Buffer
	reqLine := fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto)
	httpReqBuf.WriteString(reqLine)
	req.Header.Write(&httpReqBuf)
	httpReqBuf.WriteString("\r\n")

	// Read body if present
	var bodyBuf []byte
	if req.Body != nil {
		bodyBuf, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}

	httpReqSize := httpReqBuf.Len()
	bodySize := len(bodyBuf)

	// Build ICAP request
	var icapReq bytes.Buffer
	icapReq.WriteString(fmt.Sprintf("REQMOD %s ICAP/1.0\r\n", u.Path))
	icapReq.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
	icapReq.WriteString("User-Agent: ads-httpproxy/1.0\r\n")
	icapReq.WriteString("Allow: 204\r\n") // Allow 204 No Modifications Needed

	if bodySize > 0 {
		icapReq.WriteString(fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n", httpReqSize))
	} else {
		icapReq.WriteString(fmt.Sprintf("Encapsulated: req-hdr=0, null-body=%d\r\n", httpReqSize))
	}

	// Add preview if supported
	if c.PreviewSize > 0 && bodySize > 0 {
		previewLen := bodySize
		if previewLen > c.PreviewSize {
			previewLen = c.PreviewSize
		}
		icapReq.WriteString(fmt.Sprintf("Preview: %d\r\n", previewLen))
	}

	icapReq.WriteString("\r\n")

	// Append HTTP request headers
	icapReq.Write(httpReqBuf.Bytes())

	// Append body if present
	if bodySize > 0 {
		// Send preview or full body in chunks
		if c.PreviewSize > 0 && bodySize > c.PreviewSize {
			// Send preview
			previewData := bodyBuf[:c.PreviewSize]
			icapReq.WriteString(fmt.Sprintf("%x\r\n", len(previewData)))
			icapReq.Write(previewData)
			icapReq.WriteString("\r\n0; ieof\r\n\r\n")
		} else {
			// Send full body
			icapReq.WriteString(fmt.Sprintf("%x\r\n", bodySize))
			icapReq.Write(bodyBuf)
			icapReq.WriteString("\r\n0\r\n\r\n")
		}
	}

	// Send ICAP request
	conn.SetDeadline(time.Now().Add(c.Timeout))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write(icapReq.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send REQMOD: %w", err)
	}

	// Read ICAP response
	reader := bufio.NewReader(conn)
	return parseReqModResponse(reader, req, bodyBuf)
}

// parseReqModResponse parses ICAP REQMOD response.
func parseReqModResponse(reader *bufio.Reader, originalReq *http.Request, originalBody []byte) (*http.Request, error) {
	// Read ICAP status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	statusLine = strings.TrimSpace(statusLine)

	// Handle 204 No Modifications Needed
	if strings.HasPrefix(statusLine, "ICAP/1.0 204") {
		// Restore original body
		if len(originalBody) > 0 {
			originalReq.Body = io.NopCloser(bytes.NewReader(originalBody))
		}
		return originalReq, nil
	}

	// Handle 200 OK (modifications present)
	if !strings.HasPrefix(statusLine, "ICAP/1.0 200") {
		return nil, fmt.Errorf("ICAP REQMOD failed: %s", statusLine)
	}

	// Read ICAP headers
	icapHeaders := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			icapHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse Encapsulated header
	encapsulated := icapHeaders["Encapsulated"]
	if encapsulated == "" {
		return nil, fmt.Errorf("missing Encapsulated header")
	}

	// Parse encapsulated parts
	parts := strings.Split(encapsulated, ",")
	hasReqHdr := false
	hasReqBody := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "req-hdr=") {
			hasReqHdr = true
		} else if strings.HasPrefix(part, "req-body=") {
			hasReqBody = true
		}
	}

	// Read modified HTTP request
	if hasReqHdr {
		modifiedReq, err := http.ReadRequest(bufio.NewReader(reader))
		if err != nil {
			return nil, fmt.Errorf("failed to read modified request: %w", err)
		}

		// Read body if present
		if hasReqBody {
			bodyBuf, err := readChunkedBody(reader)
			if err != nil {
				return nil, fmt.Errorf("failed to read modified body: %w", err)
			}
			modifiedReq.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			modifiedReq.ContentLength = int64(len(bodyBuf))
		}

		// Preserve original URL (ICAP might not include full URL)
		modifiedReq.URL = originalReq.URL
		modifiedReq.RequestURI = originalReq.RequestURI

		return modifiedReq, nil
	}

	// Fallback: return original request
	if len(originalBody) > 0 {
		originalReq.Body = io.NopCloser(bytes.NewReader(originalBody))
	}
	return originalReq, nil
}

// RespMod performs an ICAP RESPMOD request (modify HTTP response).
func (c *Client) RespMod(resp *http.Response) (*http.Response, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	u, _ := url.Parse(c.ServerURL)

	// Serialize HTTP request line (required for RESPMOD context)
	var reqLineBuf bytes.Buffer
	if resp.Request != nil {
		reqLine := fmt.Sprintf("%s %s %s\r\n\r\n", resp.Request.Method, resp.Request.URL.RequestURI(), resp.Request.Proto)
		reqLineBuf.WriteString(reqLine)
	} else {
		reqLineBuf.WriteString("GET / HTTP/1.1\r\n\r\n")
	}

	// Serialize HTTP response
	var httpRespBuf bytes.Buffer
	statusLine := fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)
	httpRespBuf.WriteString(statusLine)
	resp.Header.Write(&httpRespBuf)
	httpRespBuf.WriteString("\r\n")

	// Read body if present
	var bodyBuf []byte
	if resp.Body != nil {
		bodyBuf, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}

	reqLineSize := reqLineBuf.Len()
	httpRespSize := httpRespBuf.Len()
	bodySize := len(bodyBuf)

	// Build ICAP request
	var icapReq bytes.Buffer
	icapReq.WriteString(fmt.Sprintf("RESPMOD %s ICAP/1.0\r\n", u.Path))
	icapReq.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
	icapReq.WriteString("User-Agent: ads-httpproxy/1.0\r\n")
	icapReq.WriteString("Allow: 204\r\n")

	if bodySize > 0 {
		icapReq.WriteString(fmt.Sprintf("Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n", reqLineSize, reqLineSize+httpRespSize))
	} else {
		icapReq.WriteString(fmt.Sprintf("Encapsulated: req-hdr=0, res-hdr=%d, null-body=%d\r\n", reqLineSize, reqLineSize+httpRespSize))
	}

	// Add preview if supported
	if c.PreviewSize > 0 && bodySize > 0 {
		previewLen := bodySize
		if previewLen > c.PreviewSize {
			previewLen = c.PreviewSize
		}
		icapReq.WriteString(fmt.Sprintf("Preview: %d\r\n", previewLen))
	}

	icapReq.WriteString("\r\n")

	// Append request line
	icapReq.Write(reqLineBuf.Bytes())

	// Append response headers
	icapReq.Write(httpRespBuf.Bytes())

	// Append body if present
	if bodySize > 0 {
		if c.PreviewSize > 0 && bodySize > c.PreviewSize {
			previewData := bodyBuf[:c.PreviewSize]
			icapReq.WriteString(fmt.Sprintf("%x\r\n", len(previewData)))
			icapReq.Write(previewData)
			icapReq.WriteString("\r\n0; ieof\r\n\r\n")
		} else {
			icapReq.WriteString(fmt.Sprintf("%x\r\n", bodySize))
			icapReq.Write(bodyBuf)
			icapReq.WriteString("\r\n0\r\n\r\n")
		}
	}

	// Send ICAP request
	conn.SetDeadline(time.Now().Add(c.Timeout))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write(icapReq.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send RESPMOD: %w", err)
	}

	// Read ICAP response
	reader := bufio.NewReader(conn)
	return parseRespModResponse(reader, resp, bodyBuf)
}

// parseRespModResponse parses ICAP RESPMOD response.
func parseRespModResponse(reader *bufio.Reader, originalResp *http.Response, originalBody []byte) (*http.Response, error) {
	// Read ICAP status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	statusLine = strings.TrimSpace(statusLine)

	// Handle 204 No Modifications Needed
	if strings.HasPrefix(statusLine, "ICAP/1.0 204") {
		if len(originalBody) > 0 {
			originalResp.Body = io.NopCloser(bytes.NewReader(originalBody))
		}
		return originalResp, nil
	}

	// Handle 200 OK
	if !strings.HasPrefix(statusLine, "ICAP/1.0 200") {
		return nil, fmt.Errorf("ICAP RESPMOD failed: %s", statusLine)
	}

	// Read ICAP headers
	icapHeaders := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			icapHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse Encapsulated header
	encapsulated := icapHeaders["Encapsulated"]
	if encapsulated == "" {
		return nil, fmt.Errorf("missing Encapsulated header")
	}

	// Parse encapsulated parts
	parts := strings.Split(encapsulated, ",")
	hasResHdr := false
	hasResBody := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "res-hdr=") {
			hasResHdr = true
		} else if strings.HasPrefix(part, "res-body=") {
			hasResBody = true
		}
	}

	// Skip req-hdr if present
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "req-hdr=") {
			// Read and discard request headers
			for {
				line, _ := reader.ReadString('\n')
				if strings.TrimSpace(line) == "" {
					break
				}
			}
		}
	}

	// Read modified HTTP response
	if hasResHdr {
		modifiedResp, err := http.ReadResponse(bufio.NewReader(reader), originalResp.Request)
		if err != nil {
			return nil, fmt.Errorf("failed to read modified response: %w", err)
		}

		// Read body if present
		if hasResBody {
			bodyBuf, err := readChunkedBody(reader)
			if err != nil {
				return nil, fmt.Errorf("failed to read modified body: %w", err)
			}
			modifiedResp.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			modifiedResp.ContentLength = int64(len(bodyBuf))
		}

		return modifiedResp, nil
	}

	// Fallback: return original response
	if len(originalBody) > 0 {
		originalResp.Body = io.NopCloser(bytes.NewReader(originalBody))
	}
	return originalResp, nil
}

// readChunkedBody reads HTTP chunked transfer encoding.
func readChunkedBody(reader *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer

	for {
		// Read chunk size
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		// Parse chunk size (hex)
		line = strings.TrimSpace(line)
		parts := strings.Split(line, ";")
		sizeStr := strings.TrimSpace(parts[0])

		var size int64
		fmt.Sscanf(sizeStr, "%x", &size)

		if size == 0 {
			// Last chunk
			// Read trailing headers if any
			for {
				line, _ := reader.ReadString('\n')
				if strings.TrimSpace(line) == "" {
					break
				}
			}
			break
		}

		// Read chunk data
		chunkData := make([]byte, size)
		if _, err := io.ReadFull(reader, chunkData); err != nil {
			return nil, err
		}
		buf.Write(chunkData)

		// Read trailing CRLF
		reader.ReadString('\n')
	}

	return buf.Bytes(), nil
}

// Close closes all connections in the pool.
func (c *Client) Close() error {
	close(c.connPool)
	for conn := range c.connPool {
		conn.Close()
	}
	return nil
}
