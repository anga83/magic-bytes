package detector

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

const maxJSONCheckSize = 2 * 1024 * 1024 // 2 MiB

var (
	reMDHeading2Plus = regexp.MustCompile(`(?m)^#{2,6}[ \t]+\S`)
	reMDHeading1     = regexp.MustCompile(`(?m)^#[ \t]+\S`)
	reMDLink         = regexp.MustCompile(`!?\[[^\]\n]+\]\([^)\s\n]+\)`)
	reMDTableSep     = regexp.MustCompile(`(?m)^\|?[ \t]*:?-{3,}:?[ \t]*(\|[ \t]*:?-{3,}:?[ \t]*)+\|?[ \t]*$`)
	reMDTaskList     = regexp.MustCompile(`(?m)^[ \t]*[-*][ \t]+\[[ xX]\][ \t]+\S`)
	reMDList         = regexp.MustCompile(`(?m)^[ \t]*[-*][ \t]+\S`)
	reMDBlockquote   = regexp.MustCompile(`(?m)^>[ \t]+\S`)
	reMDBold         = regexp.MustCompile(`\*\*[^*\n]+\*\*`)
	reHTMLCloseTag   = regexp.MustCompile(`(?i)</(html|head|body|title|div|span|p|h[1-6]|table|ul|ol|li|a|section|article|header|footer|form|script|style)>`)
	reHTMLOpenTag    = regexp.MustCompile(`(?i)<(html|head|body|title|meta|link|div|span|p|h[1-6]|table|ul|ol|form|section|article|header|footer|script|style)(\s|>|/>)`)
)

// detectTextFormat inspects plain text content (when no binary magic bytes or
// shebang matched) for unambiguous JSON, HTML, or Markdown structure.
func detectTextFormat(r io.ReadSeeker, header []byte, size int64) (Result, bool) {
	if !isPrintableText(string(header)) {
		return Result{}, false
	}

	if res, ok := detectJSON(r, header, size); ok {
		return res, true
	}
	if res, ok := detectHTML(header); ok {
		return res, true
	}
	if res, ok := detectMarkdown(header); ok {
		return res, true
	}

	return Result{}, false
}

func detectJSON(r io.ReadSeeker, header []byte, size int64) (Result, bool) {
	trimmedHead := bytes.TrimSpace(header)
	if len(trimmedHead) < 2 {
		return Result{}, false
	}
	first := trimmedHead[0]
	if first != '{' && first != '[' {
		return Result{}, false
	}

	data := header
	if size > int64(len(header)) {
		if size > maxJSONCheckSize {
			return Result{}, false
		}
		full, ok := readAt(r, 0, int(size))
		if !ok {
			return Result{}, false
		}
		data = full
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 {
		return Result{}, false
	}
	last := trimmed[len(trimmed)-1]
	if (first == '{' && last != '}') || (first == '[' && last != ']') {
		return Result{}, false
	}

	if !json.Valid(trimmed) {
		return Result{}, false
	}

	return Result{
		Name:        "JSON",
		Description: "JavaScript Object Notation",
		Extension:   ".json",
		MIMEType:    "application/json",
		Category:    "Data",
		Matched:     true,
	}, true
}

func detectHTML(header []byte) (Result, bool) {
	s := strings.TrimSpace(string(header))
	lower := strings.ToLower(s)

	if strings.HasPrefix(lower, "<!doctype html") ||
		strings.HasPrefix(lower, "<html") && (len(lower) == 5 || lower[5] == '>' || lower[5] == ' ' || lower[5] == '\t' || lower[5] == '\n' || lower[5] == '\r') {
		return htmlResult(), true
	}

	if reHTMLOpenTag.MatchString(s) && reHTMLCloseTag.MatchString(s) {
		return htmlResult(), true
	}

	return Result{}, false
}

func htmlResult() Result {
	return Result{
		Name:        "HTML",
		Description: "HyperText Markup Language",
		Extension:   ".html",
		Aliases:     []string{".htm"},
		MIMEType:    "text/html",
		Category:    "Document",
		Matched:     true,
	}
}

func detectMarkdown(header []byte) (Result, bool) {
	s := string(header)
	score := 0

	if reMDHeading2Plus.MatchString(s) {
		score += 2
	} else if reMDHeading1.MatchString(s) {
		score++
	}

	if reMDLink.MatchString(s) {
		score += 2
	}
	if hasFencedCodeBlock(s) {
		score += 2
	}
	if reMDTableSep.MatchString(s) {
		score += 2
	}
	if reMDTaskList.MatchString(s) {
		score += 2
	} else if reMDList.MatchString(s) {
		score++
	}
	if reMDBlockquote.MatchString(s) {
		score++
	}
	if reMDBold.MatchString(s) {
		score++
	}

	if score < 2 {
		return Result{}, false
	}

	return Result{
		Name:        "Markdown",
		Description: "Markdown Document",
		Extension:   ".md",
		Aliases:     []string{".markdown"},
		MIMEType:    "text/markdown",
		Category:    "Document",
		Matched:     true,
	}, true
}

func hasFencedCodeBlock(s string) bool {
	fences := 0
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fences++
			if fences >= 2 {
				return true
			}
		}
	}
	return false
}
