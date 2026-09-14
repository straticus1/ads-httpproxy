package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

func runCodec(command string, args []string, input io.Reader, output io.Writer) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(output)
	encoding := fs.String("encoding", "utf8", "Encoding or comma-separated transformation chain")
	data := fs.String("data", "", "Literal input; defaults to stdin")
	file := fs.String("file", "", "Input file; use - for stdin")
	limit := fs.Int64("max-bytes", 16<<20, "Maximum input and decoded output size (up to 64 MiB)")
	replace := fs.Bool("replace-invalid", false, "Replace invalid UTF-8 bytes instead of rejecting them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *limit < 1 || *limit > 64<<20 {
		return fmt.Errorf("max-bytes must be between 1 and 67108864")
	}
	supplied := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "data" {
			supplied = true
		}
	})
	if supplied && *file != "" {
		return fmt.Errorf("choose -data or -file")
	}
	if supplied {
		input = strings.NewReader(*data)
	} else if *file != "" && *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}
	content, err := readBounded(input, *limit)
	if err != nil {
		return err
	}
	for _, name := range strings.Split(*encoding, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		content, err = codec(command, name, content, *limit, *replace)
		if err != nil {
			return fmt.Errorf("%s %s: %w", command, name, err)
		}
		if int64(len(content)) > *limit {
			return fmt.Errorf("output exceeds max-bytes (%d)", *limit)
		}
	}
	_, err = output.Write(content)
	return err
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("input/output exceeds max-bytes (%d)", limit)
	}
	return content, nil
}
func compactWhitespace(content []byte) string {
	return strings.Join(strings.Fields(string(content)), "")
}
func decodeBase64(content []byte, urlSafe bool) ([]byte, error) {
	value := compactWhitespace(content)
	encoding := base64.StdEncoding.Strict()
	raw := base64.RawStdEncoding.Strict()
	if urlSafe {
		encoding = base64.URLEncoding.Strict()
		raw = base64.RawURLEncoding.Strict()
	}
	if strings.Contains(value, "=") {
		return encoding.DecodeString(value)
	}
	return raw.DecodeString(value)
}
func codec(command, name string, content []byte, limit int64, replace bool) ([]byte, error) {
	if command == "encode" {
		switch name {
		case "base64":
			return []byte(base64.StdEncoding.EncodeToString(content)), nil
		case "base64url":
			return []byte(base64.RawURLEncoding.EncodeToString(content)), nil
		case "hex":
			return []byte(hex.EncodeToString(content)), nil
		case "url", "percent":
			return []byte(url.PathEscape(string(content))), nil
		case "form", "query":
			return []byte(url.QueryEscape(string(content))), nil
		case "html":
			return []byte(html.EscapeString(string(content))), nil
		case "json-string":
			if !utf8.Valid(content) {
				return nil, fmt.Errorf("invalid UTF-8")
			}
			return json.Marshal(string(content))
		case "quoted-printable":
			var out bytes.Buffer
			w := quotedprintable.NewWriter(&out)
			if _, err := w.Write(content); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return out.Bytes(), nil
		case "gzip", "deflate", "deflate-raw":
			var out bytes.Buffer
			var w io.WriteCloser
			switch name {
			case "gzip":
				w = gzip.NewWriter(&out)
			case "deflate":
				w = zlib.NewWriter(&out)
			default:
				writer, err := flate.NewWriter(&out, flate.DefaultCompression)
				if err != nil {
					return nil, err
				}
				w = writer
			}
			if _, err := w.Write(content); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return out.Bytes(), nil
		case "chunked":
			var out bytes.Buffer
			w := httputil.NewChunkedWriter(&out)
			if _, err := w.Write(content); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			out.WriteString("\r\n")
			return out.Bytes(), nil
		case "utf8", "utf-8", "identity": // Validate below.
		default:
			return nil, fmt.Errorf("unsupported encoding: %s", name)
		}
	}
	switch name {
	case "utf8", "utf-8":
		content = bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})
		if !utf8.Valid(content) {
			if replace {
				return []byte(strings.ToValidUTF8(string(content), "�")), nil
			}
			return nil, fmt.Errorf("invalid UTF-8; use -replace-invalid to repair")
		}
		return content, nil
	case "identity":
		return content, nil
	case "base64":
		return decodeBase64(content, false)
	case "base64url":
		return decodeBase64(content, true)
	case "hex":
		return hex.DecodeString(compactWhitespace(content))
	case "url", "percent":
		value, err := url.PathUnescape(string(content))
		return []byte(value), err
	case "form", "query":
		value, err := url.QueryUnescape(string(content))
		return []byte(value), err
	case "html":
		return []byte(html.UnescapeString(string(content))), nil
	case "json-string":
		var value string
		if err := json.Unmarshal(content, &value); err != nil {
			return nil, err
		}
		return []byte(value), nil
	case "json":
		var out bytes.Buffer
		if err := json.Indent(&out, content, "", "  "); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	case "quoted-printable":
		return readBounded(quotedprintable.NewReader(bytes.NewReader(content)), limit)
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readBounded(reader, limit)
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(content))
		if err == nil {
			defer reader.Close()
			return readBounded(reader, limit)
		}
		reader = flate.NewReader(bytes.NewReader(content))
		defer reader.Close()
		return readBounded(reader, limit)
	case "deflate-raw":
		reader := flate.NewReader(bytes.NewReader(content))
		defer reader.Close()
		return readBounded(reader, limit)
	case "chunked":
		return readBounded(httputil.NewChunkedReader(bytes.NewReader(content)), limit)
	case "http":
		return decodeHTTP(content, limit)
	case "jwt":
		parts := strings.Split(strings.TrimSpace(string(content)), ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("expected a three-part JWT")
		}
		header, err := decodeBase64([]byte(parts[0]), true)
		if err != nil {
			return nil, err
		}
		payload, err := decodeBase64([]byte(parts[1]), true)
		if err != nil {
			return nil, err
		}
		if !json.Valid(header) || !json.Valid(payload) {
			return nil, fmt.Errorf("JWT header and payload must be JSON")
		}
		return json.MarshalIndent(map[string]any{"header": json.RawMessage(header), "payload": json.RawMessage(payload), "signature_verified": false}, "", "  ")
	case "utf16le", "utf16be", "latin1", "windows-1252":
		charset := map[string]string{"utf16le": "utf-16le", "utf16be": "utf-16be", "latin1": "iso-8859-1", "windows-1252": "windows-1252"}[name]
		return decodeCharset(content, charset, limit)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", name)
	}
}
func decodeCharset(content []byte, charset string, limit int64) ([]byte, error) {
	if strings.EqualFold(charset, "utf-8") || strings.EqualFold(charset, "utf8") {
		return codec("decode", "utf8", content, limit, false)
	}
	if strings.EqualFold(charset, "iso-8859-1") || strings.EqualFold(charset, "latin1") {
		return readBounded(transform.NewReader(bytes.NewReader(content), charmap.ISO8859_1.NewDecoder()), limit)
	}
	encoding, err := htmlindex.Get(charset)
	if err != nil {
		return nil, fmt.Errorf("unsupported charset %q: %w", charset, err)
	}
	return readBounded(transform.NewReader(bytes.NewReader(content), encoding.NewDecoder()), limit)
}

// decodeHTTP handles one raw HTTP/1 request or response, transfer framing first,
// then Content-Encoding in reverse order and the declared text charset.
func decodeHTTP(content []byte, limit int64) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(content))
	var body io.ReadCloser
	var headers http.Header
	if bytes.HasPrefix(content, []byte("HTTP/")) {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, err
		}
		body = response.Body
		headers = response.Header
	} else {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return nil, err
		}
		body = request.Body
		headers = request.Header
	}
	defer body.Close()
	result, err := readBounded(body, limit)
	if err != nil {
		return nil, err
	}
	return decodeEntity(result, headers, limit)
}

func decodeEntity(result []byte, headers http.Header, limit int64) ([]byte, error) {
	var err error
	encodings := strings.Split(strings.Join(headers.Values("Content-Encoding"), ","), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		name := strings.ToLower(strings.TrimSpace(encodings[i]))
		if name == "" || name == "identity" {
			continue
		}
		if name != "gzip" && name != "deflate" {
			return nil, fmt.Errorf("unsupported HTTP content encoding: %s", name)
		}
		result, err = codec("decode", name, result, limit, false)
		if err != nil {
			return nil, err
		}
	}
	if value := headers.Get("Content-Type"); value != "" {
		_, params, err := mime.ParseMediaType(value)
		if err != nil {
			return nil, err
		}
		if charset := params["charset"]; charset != "" {
			return decodeCharset(result, charset, limit)
		}
	}
	return result, nil
}
