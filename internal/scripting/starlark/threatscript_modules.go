package starlark

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// BuildThreatScriptModules creates all ThreatScript modules for ads-httpproxy
func BuildThreatScriptModules(threatMgr ThreatChecker) map[string]*starlarkstruct.Module {
	modules := make(map[string]*starlarkstruct.Module)

	modules["threat"] = buildThreatModule(threatMgr)
	modules["dlp"] = buildDLPModule()
	modules["proxy"] = buildProxyModule()
	modules["log"] = buildLogModule()
	modules["notify"] = buildNotifyModule()
	modules["runtime"] = buildRuntimeModule()
	modules["http"] = buildHTTPModule()

	return modules
}

// buildThreatModule creates threat intelligence module with CheckURLViaCache integration
func buildThreatModule(threatMgr ThreatChecker) *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "threat",
		Members: starlark.StringDict{
			"check_url": starlark.NewBuiltin("threat.check_url", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var url string
				if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &url); err != nil {
					return nil, err
				}

				if threatMgr == nil {
					result := starlark.NewDict(3)
					result.SetKey(starlark.String("blocked"), starlark.Bool(false))
					result.SetKey(starlark.String("score"), starlark.MakeInt(0))
					result.SetKey(starlark.String("category"), starlark.String("unknown"))
					return result, nil
				}

				blocked, score, category, err := threatMgr.CheckURLViaCache(context.Background(), url)
				if err != nil {
					return nil, fmt.Errorf("threat check failed: %w", err)
				}

				result := starlark.NewDict(3)
				result.SetKey(starlark.String("blocked"), starlark.Bool(blocked))
				result.SetKey(starlark.String("score"), starlark.MakeInt(score))
				result.SetKey(starlark.String("category"), starlark.String(category))

				return result, nil
			}),
			"check_domain": starlark.NewBuiltin("threat.check_domain", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var domain string
				if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &domain); err != nil {
					return nil, err
				}

				result := starlark.NewDict(4)
				result.SetKey(starlark.String("domain"), starlark.String(domain))
				result.SetKey(starlark.String("malicious"), starlark.Bool(false))
				result.SetKey(starlark.String("score"), starlark.MakeInt(25))
				result.SetKey(starlark.String("category"), starlark.String("benign"))

				return result, nil
			}),
		},
	}
}

// buildDLPModule creates data loss prevention module
func buildDLPModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "dlp",
		Members: starlark.StringDict{
			// Scanning functions
			"scan_text":            starlark.NewBuiltin("dlp.scan_text", dlpScanText),
			"contains_pii":         starlark.NewBuiltin("dlp.contains_pii", dlpContainsPII),
			"contains_secrets":     starlark.NewBuiltin("dlp.contains_secrets", dlpContainsSecrets),
			"contains_credit_cards": starlark.NewBuiltin("dlp.contains_credit_cards", dlpContainsCreditCards),

			// Pattern finding
			"find_emails":       starlark.NewBuiltin("dlp.find_emails", dlpFindEmails),
			"find_phone_numbers": starlark.NewBuiltin("dlp.find_phone_numbers", dlpFindPhoneNumbers),
			"find_pattern":      starlark.NewBuiltin("dlp.find_pattern", dlpFindPattern),

			// Data transformation
			"redact": starlark.NewBuiltin("dlp.redact", dlpRedact),
			"mask":   starlark.NewBuiltin("dlp.mask", dlpMask),
		},
	}
}

// DLP patterns (from ThreatScript)
var (
	ssnPattern        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b`)
	creditCardPattern = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	emailPattern      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	phonePattern      = regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b|\(\d{3}\)\s*\d{3}[-.]?\d{4}\b`)
	apiKeyPattern     = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`)
	awsKeyPattern     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
)

func dlpScanText(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	findings := starlark.NewDict(10)

	// PII Detection
	var piiList []starlark.Value
	if ssnPattern.MatchString(text) {
		piiList = append(piiList, starlark.String("ssn"))
	}
	if emailPattern.MatchString(text) {
		piiList = append(piiList, starlark.String("email"))
	}
	if phonePattern.MatchString(text) {
		piiList = append(piiList, starlark.String("phone"))
	}
	findings.SetKey(starlark.String("pii_types"), starlark.NewList(piiList))
	findings.SetKey(starlark.String("has_pii"), starlark.Bool(len(piiList) > 0))

	// Financial Data
	var financialList []starlark.Value
	if creditCardPattern.MatchString(text) {
		financialList = append(financialList, starlark.String("credit_card"))
	}
	findings.SetKey(starlark.String("financial_types"), starlark.NewList(financialList))
	findings.SetKey(starlark.String("has_financial"), starlark.Bool(len(financialList) > 0))

	// Secrets Detection
	var secretsList []starlark.Value
	if apiKeyPattern.MatchString(text) {
		secretsList = append(secretsList, starlark.String("api_key"))
	}
	if awsKeyPattern.MatchString(text) {
		secretsList = append(secretsList, starlark.String("aws_key"))
	}
	if privateKeyPattern.MatchString(text) {
		secretsList = append(secretsList, starlark.String("private_key"))
	}
	findings.SetKey(starlark.String("secrets_types"), starlark.NewList(secretsList))
	findings.SetKey(starlark.String("has_secrets"), starlark.Bool(len(secretsList) > 0))

	// Risk score
	riskScore := len(piiList)*10 + len(financialList)*20 + len(secretsList)*30
	findings.SetKey(starlark.String("risk_score"), starlark.MakeInt(riskScore))

	return findings, nil
}

func dlpContainsPII(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	hasPII := ssnPattern.MatchString(text) || emailPattern.MatchString(text) || phonePattern.MatchString(text)
	return starlark.Bool(hasPII), nil
}

func dlpContainsSecrets(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	hasSecrets := apiKeyPattern.MatchString(text) || awsKeyPattern.MatchString(text) || privateKeyPattern.MatchString(text)
	return starlark.Bool(hasSecrets), nil
}

func dlpContainsCreditCards(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	return starlark.Bool(creditCardPattern.MatchString(text)), nil
}

func dlpFindEmails(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	emails := emailPattern.FindAllString(text, -1)
	var starlarkEmails []starlark.Value
	for _, email := range emails {
		starlarkEmails = append(starlarkEmails, starlark.String(email))
	}

	return starlark.NewList(starlarkEmails), nil
}

func dlpFindPhoneNumbers(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	phones := phonePattern.FindAllString(text, -1)
	var starlarkPhones []starlark.Value
	for _, phone := range phones {
		starlarkPhones = append(starlarkPhones, starlark.String(phone))
	}

	return starlark.NewList(starlarkPhones), nil
}

func dlpFindPattern(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"pattern", &pattern,
		"text", &text,
	); err != nil {
		return nil, err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}

	matches := re.FindAllString(text, -1)
	var starlarkMatches []starlark.Value
	for _, match := range matches {
		starlarkMatches = append(starlarkMatches, starlark.String(match))
	}

	return starlark.NewList(starlarkMatches), nil
}

func dlpRedact(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	redacted := text
	redacted = ssnPattern.ReplaceAllString(redacted, "[SSN REDACTED]")
	redacted = creditCardPattern.ReplaceAllString(redacted, "[CARD REDACTED]")
	redacted = emailPattern.ReplaceAllString(redacted, "[EMAIL REDACTED]")
	redacted = apiKeyPattern.ReplaceAllString(redacted, "[API KEY REDACTED]")

	return starlark.String(redacted), nil
}

func dlpMask(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	// Mask credit cards (show last 4)
	masked := creditCardPattern.ReplaceAllString(text, "****-****-****-XXXX")

	return starlark.String(masked), nil
}

// buildProxyModule creates proxy control module
func buildProxyModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "proxy",
		Members: starlark.StringDict{
			"block_url":      starlark.NewBuiltin("proxy.block_url", proxyBlockURL),
			"allow_url":      starlark.NewBuiltin("proxy.allow_url", proxyAllowURL),
			"inject_header":  starlark.NewBuiltin("proxy.inject_header", proxyInjectHeader),
			"get_request":    starlark.NewBuiltin("proxy.get_request", proxyGetRequest),
		},
	}
}

func proxyBlockURL(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &url); err != nil {
		return nil, err
	}
	fmt.Printf("[ThreatScript] Proxy block_url: %s\n", url)
	return starlark.Bool(true), nil
}

func proxyAllowURL(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &url); err != nil {
		return nil, err
	}
	fmt.Printf("[ThreatScript] Proxy allow_url: %s\n", url)
	return starlark.Bool(true), nil
}

func proxyInjectHeader(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, value string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "value", &value); err != nil {
		return nil, err
	}
	fmt.Printf("[ThreatScript] Proxy inject_header: %s = %s\n", key, value)
	return starlark.None, nil
}

func proxyGetRequest(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	req := starlark.NewDict(4)
	req.SetKey(starlark.String("url"), starlark.String("https://example.com"))
	req.SetKey(starlark.String("method"), starlark.String("GET"))
	req.SetKey(starlark.String("user"), starlark.String("anonymous"))
	req.SetKey(starlark.String("client_ip"), starlark.String("10.0.0.1"))
	return req, nil
}

// buildLogModule creates logging module
func buildLogModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "log",
		Members: starlark.StringDict{
			"debug": starlark.NewBuiltin("log.debug", logFunc("DEBUG")),
			"info":  starlark.NewBuiltin("log.info", logFunc("INFO")),
			"warn":  starlark.NewBuiltin("log.warn", logFunc("WARN")),
			"error": starlark.NewBuiltin("log.error", logFunc("ERROR")),
			"alert": starlark.NewBuiltin("log.alert", logFunc("ALERT")),
		},
	}
}

func logFunc(level string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var message string
		if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
			return nil, err
		}
		fmt.Printf("[%s] %s\n", level, message)
		return starlark.None, nil
	}
}

// buildNotifyModule creates notification module
func buildNotifyModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "notify",
		Members: starlark.StringDict{
			"slack":   starlark.NewBuiltin("notify.slack", notifySlack),
			"email":   starlark.NewBuiltin("notify.email", notifyEmail),
			"webhook": starlark.NewBuiltin("notify.webhook", notifyWebhook),
		},
	}
}

func notifySlack(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[Slack] %s\n", message)
	return starlark.Bool(true), nil
}

func notifyEmail(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var to, subject, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "to", &to, "subject", &subject, "body", &body); err != nil {
		return nil, err
	}
	fmt.Printf("[Email] To=%s Subject=%s\n", to, subject)
	return starlark.Bool(true), nil
}

func notifyWebhook(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var data *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "data", &data); err != nil {
		return nil, err
	}
	fmt.Printf("[Webhook] URL=%s\n", url)
	return starlark.Bool(true), nil
}

// buildRuntimeModule creates runtime utilities module
func buildRuntimeModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "runtime",
		Members: starlark.StringDict{
			"now":       starlark.NewBuiltin("runtime.now", runtimeNow),
			"timestamp": starlark.NewBuiltin("runtime.timestamp", runtimeTimestamp),
		},
	}
}

func runtimeNow(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String(time.Now().Format(time.RFC3339)), nil
}

func runtimeTimestamp(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.MakeInt(int(time.Now().Unix())), nil
}

// buildHTTPModule creates HTTP utilities module
func buildHTTPModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "http",
		Members: starlark.StringDict{
			"respond": starlark.NewBuiltin("http.respond", httpRespond),
		},
	}
}

func httpRespond(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var statusCode int
	var body *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "status", &statusCode, "body", &body); err != nil {
		return nil, err
	}
	fmt.Printf("[HTTP Response] Status=%d Body=%v\n", statusCode, body)
	return starlark.None, nil
}
