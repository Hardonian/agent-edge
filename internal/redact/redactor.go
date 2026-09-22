package redact

import (
	"regexp"
	"strings"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// SecretFinding details a detected potential secret.
type SecretFinding struct {
	Type        string `json:"type"`
	PatternName string `json:"pattern_name"`
	MatchStart  int    `json:"match_start"`
	MatchEnd    int    `json:"match_end"`
	Sample      string `json:"sample"` // masked preview (e.g. sk-ant-...4a1b)
}

type secretPattern struct {
	name    string
	regex   *regexp.Regexp
	replace string
}

var defaultPatterns = []secretPattern{
	{
		name:    "Anthropic API Key",
		regex:   regexp.MustCompile(`\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b`),
		replace: "[REDACTED_ANTHROPIC_KEY]",
	},
	{
		name:    "OpenAI API Key",
		regex:   regexp.MustCompile(`\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,})\b`),
		replace: "[REDACTED_OPENAI_KEY]",
	},
	{
		name:    "Google / Gemini API Key",
		regex:   regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		replace: "[REDACTED_GOOGLE_KEY]",
	},
	{
		name:    "AWS Access Key ID",
		regex:   regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		replace: "[REDACTED_AWS_KEY]",
	},
	{
		name:    "GitHub Token",
		regex:   regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{36,})\b`),
		replace: "[REDACTED_GITHUB_TOKEN]",
	},
	{
		name:    "Bearer Token",
		regex:   regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)`),
		replace: "Bearer [REDACTED_TOKEN]",
	},
	{
		name:    "JSON Web Token (JWT)",
		regex:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		replace: "[REDACTED_JWT]",
	},
	{
		name:    "Database URL with Credentials",
		regex:   regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:([^@\s]+)@`),
		replace: "$1://[USER]:[REDACTED_PASS]@",
	},
	{
		name:    "Private Key Block",
		regex:   regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
		replace: "[REDACTED_PRIVATE_KEY]",
	},
	{
		name:    "Generic Password / Secret Assignment",
		regex:   regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|api_key|apikey|access_token|client_secret)["']?\s*[:=]\s*["'])([^"'\r\n]{4,})(["'])`),
		replace: "${1}[REDACTED_SECRET]${3}",
	},
}

// Redactor handles data sanitization and secret inspection.
type Redactor struct {
	patterns []secretPattern
}

// New creates a Redactor with built-in standard patterns.
func New() *Redactor {
	return &Redactor{
		patterns: defaultPatterns,
	}
}

// AddPattern adds a custom user-defined secret redaction regex.
func (r *Redactor) AddPattern(name, pattern, replacement string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.patterns = append(r.patterns, secretPattern{
		name:    name,
		regex:   compiled,
		replace: replacement,
	})
	return nil
}

// RedactText replaces all detected secrets with redaction placeholders.
func (r *Redactor) RedactText(s string) string {
	out := s
	for _, p := range r.patterns {
		out = p.regex.ReplaceAllString(out, p.replace)
	}
	return out
}

// RedactMap recursively walks and redacts string values and sensitive keys in a map.
func (r *Redactor) RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		lowerKey := strings.ToLower(k)
		if isSensitiveKey(lowerKey) {
			out[k] = "[REDACTED_SENSITIVE_FIELD]"
			continue
		}

		switch val := v.(type) {
		case string:
			out[k] = r.RedactText(val)
		case map[string]any:
			out[k] = r.RedactMap(val)
		case []any:
			out[k] = r.redactSlice(val)
		default:
			out[k] = v
		}
	}
	return out
}

func (r *Redactor) redactSlice(s []any) []any {
	out := make([]any, len(s))
	for i, item := range s {
		switch val := item.(type) {
		case string:
			out[i] = r.RedactText(val)
		case map[string]any:
			out[i] = r.RedactMap(val)
		case []any:
			out[i] = r.redactSlice(val)
		default:
			out[i] = item
		}
	}
	return out
}

func isSensitiveKey(k string) bool {
	return strings.Contains(k, "authorization") ||
		strings.Contains(k, "cookie") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "apikey") ||
		strings.Contains(k, "api_key") ||
		strings.Contains(k, "private_key")
}

// RedactEvent redacts all strings, attributes, and payloads in an event.
func (r *Redactor) RedactEvent(ev *apcap.Event) *apcap.Event {
	clone := ev.Clone()

	clone.Operation = r.RedactText(clone.Operation)
	if clone.Attributes != nil {
		clone.Attributes = r.RedactMap(clone.Attributes)
	}
	if clone.Payload != nil {
		if clone.Payload.Preview != "" {
			clone.Payload.Preview = r.RedactText(clone.Payload.Preview)
			clone.Payload.Redacted = true
		}
	}
	return clone
}

// RedactCapture produces a fully redacted copy of a Capture.
func (r *Redactor) RedactCapture(c *apcap.Capture) *apcap.Capture {
	out := &apcap.Capture{
		Manifest: c.Manifest,
		Metadata: c.Metadata,
		Events:   make([]apcap.Event, len(c.Events)),
	}
	out.Manifest.RedactionMode = "sanitized_content"

	for i := range c.Events {
		out.Events[i] = *r.RedactEvent(&c.Events[i])
	}
	return out
}

// InspectSecrets returns all detected potential secret locations in text.
func (r *Redactor) InspectSecrets(s string) []SecretFinding {
	var findings []SecretFinding
	for _, p := range r.patterns {
		matches := p.regex.FindAllStringIndex(s, -1)
		for _, m := range matches {
			sub := s[m[0]:m[1]]
			masked := maskSecret(sub)
			findings = append(findings, SecretFinding{
				Type:        "secret",
				PatternName: p.name,
				MatchStart:  m[0],
				MatchEnd:    m[1],
				Sample:      masked,
			})
		}
	}
	return findings
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	prefixLen := 4
	suffixLen := 4
	if len(s) < 12 {
		prefixLen = 2
		suffixLen = 2
	}
	return s[:prefixLen] + "..." + s[len(s)-suffixLen:]
}
