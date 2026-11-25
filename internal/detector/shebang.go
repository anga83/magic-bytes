package detector

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

type shebangSpec struct {
	Name        string
	Description string
	Extension   string
	Aliases     []string
	MIMEType    string
}

var shebangInterpreters = map[string]shebangSpec{
	"python":     {Name: "Python Script", Description: "Python Script", Extension: ".py", MIMEType: "text/x-python"},
	"pypy":       {Name: "Python Script", Description: "PyPy Python Script", Extension: ".py", MIMEType: "text/x-python"},
	"sh":         {Name: "Shell Script", Description: "POSIX Shell Script", Extension: ".sh", MIMEType: "text/x-shellscript"},
	"dash":       {Name: "Shell Script", Description: "Dash Shell Script", Extension: ".sh", MIMEType: "text/x-shellscript"},
	"ash":        {Name: "Shell Script", Description: "Ash Shell Script", Extension: ".sh", MIMEType: "text/x-shellscript"},
	"ksh":        {Name: "Shell Script", Description: "KornShell Script", Extension: ".sh", Aliases: []string{".ksh"}, MIMEType: "text/x-shellscript"},
	"mksh":       {Name: "Shell Script", Description: "MirBSD KornShell Script", Extension: ".sh", Aliases: []string{".ksh"}, MIMEType: "text/x-shellscript"},
	"bash":       {Name: "Bash Script", Description: "Bourne-Again Shell Script", Extension: ".sh", Aliases: []string{".bash"}, MIMEType: "text/x-shellscript"},
	"zsh":        {Name: "Zsh Script", Description: "Z Shell Script", Extension: ".zsh", Aliases: []string{".sh"}, MIMEType: "text/x-shellscript"},
	"fish":       {Name: "Fish Script", Description: "Fish Shell Script", Extension: ".fish", MIMEType: "text/x-shellscript"},
	"node":       {Name: "JavaScript", Description: "Node.js Script", Extension: ".js", Aliases: []string{".mjs", ".cjs"}, MIMEType: "text/javascript"},
	"nodejs":     {Name: "JavaScript", Description: "Node.js Script", Extension: ".js", Aliases: []string{".mjs", ".cjs"}, MIMEType: "text/javascript"},
	"bun":        {Name: "JavaScript", Description: "Bun Script", Extension: ".js", Aliases: []string{".ts", ".mjs"}, MIMEType: "text/javascript"},
	"deno":       {Name: "TypeScript", Description: "Deno Script", Extension: ".ts", Aliases: []string{".js"}, MIMEType: "text/typescript"},
	"ts-node":    {Name: "TypeScript", Description: "TypeScript Script", Extension: ".ts", MIMEType: "text/typescript"},
	"tsx":        {Name: "TypeScript", Description: "TypeScript Script", Extension: ".ts", MIMEType: "text/typescript"},
	"ruby":       {Name: "Ruby Script", Description: "Ruby Script", Extension: ".rb", MIMEType: "text/x-ruby"},
	"jruby":      {Name: "Ruby Script", Description: "JRuby Script", Extension: ".rb", MIMEType: "text/x-ruby"},
	"perl":       {Name: "Perl Script", Description: "Perl Script", Extension: ".pl", MIMEType: "text/x-perl"},
	"php":        {Name: "PHP Script", Description: "PHP Script", Extension: ".php", MIMEType: "text/x-php"},
	"lua":        {Name: "Lua Script", Description: "Lua Script", Extension: ".lua", MIMEType: "text/x-lua"},
	"luajit":     {Name: "Lua Script", Description: "LuaJIT Script", Extension: ".lua", MIMEType: "text/x-lua"},
	"awk":        {Name: "AWK Script", Description: "AWK Script", Extension: ".awk", MIMEType: "text/x-awk"},
	"gawk":       {Name: "AWK Script", Description: "GNU AWK Script", Extension: ".awk", MIMEType: "text/x-awk"},
	"mawk":       {Name: "AWK Script", Description: "MAWK Script", Extension: ".awk", MIMEType: "text/x-awk"},
	"nawk":       {Name: "AWK Script", Description: "NAWK Script", Extension: ".awk", MIMEType: "text/x-awk"},
	"pwsh":       {Name: "PowerShell Script", Description: "PowerShell Script", Extension: ".ps1", MIMEType: "text/x-powershell"},
	"powershell": {Name: "PowerShell Script", Description: "PowerShell Script", Extension: ".ps1", MIMEType: "text/x-powershell"},
	"rscript":    {Name: "R Script", Description: "R Script", Extension: ".R", Aliases: []string{".r"}, MIMEType: "text/x-r"},
	"tclsh":      {Name: "Tcl Script", Description: "Tcl Script", Extension: ".tcl", MIMEType: "text/x-tcl"},
	"wish":       {Name: "Tcl Script", Description: "Tcl/Tk Script", Extension: ".tcl", MIMEType: "text/x-tcl"},
	"sed":        {Name: "Sed Script", Description: "Sed Script", Extension: ".sed", MIMEType: "text/x-sed"},
	"expect":     {Name: "Expect Script", Description: "Expect Script", Extension: ".exp", MIMEType: "text/x-expect"},
	"groovy":     {Name: "Groovy Script", Description: "Groovy Script", Extension: ".groovy", MIMEType: "text/x-groovy"},
	"scala":      {Name: "Scala Script", Description: "Scala Script", Extension: ".scala", MIMEType: "text/x-scala"},
	"swift":      {Name: "Swift Script", Description: "Swift Script", Extension: ".swift", MIMEType: "text/x-swift"},
	"osascript":  {Name: "AppleScript", Description: "AppleScript", Extension: ".scpt", Aliases: []string{".applescript"}, MIMEType: "text/x-applescript"},
}

func inspectShebang(r io.ReadSeeker, size int64) (Result, bool) {
	limit := 256
	if size < int64(limit) {
		limit = int(size)
	}
	buf, ok := readAt(r, 0, limit)
	if !ok || len(buf) < 3 {
		return Result{}, false
	}

	if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
		buf = buf[:idx]
	}
	line := strings.TrimSpace(strings.TrimPrefix(string(buf), "#!"))
	if line == "" || !isPrintableText(line) {
		return Result{}, false
	}

	interp := extractInterpreter(line)
	if interp == "" {
		return Result{}, false
	}

	if spec, found := lookupShebangSpec(interp); found {
		return Result{
			Name:        spec.Name,
			Description: spec.Description,
			Extension:   spec.Extension,
			Aliases:     spec.Aliases,
			MIMEType:    spec.MIMEType,
			Category:    "Script",
			Matched:     true,
		}, true
	}

	return Result{
		Name:        "Script",
		Description: "Executable Script (" + interp + ")",
		MIMEType:    "text/plain",
		Category:    "Script",
		Matched:     true,
	}, true
}

func isPrintableText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || (unicode.IsControl(r) && r != '\t') {
			return false
		}
	}
	return true
}

func extractInterpreter(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}

	cmd := filepath.Base(fields[0])
	if cmd != "env" {
		return strings.ToLower(cmd)
	}

	for _, arg := range fields[1:] {
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
			continue
		}
		return strings.ToLower(filepath.Base(arg))
	}
	return ""
}

func lookupShebangSpec(interp string) (shebangSpec, bool) {
	if spec, ok := shebangInterpreters[interp]; ok {
		return spec, true
	}

	// Handle versioned interpreters such as python3, python3.12, perl5, php8.3.
	trimmed := strings.TrimRight(interp, "0123456789.")
	if trimmed != "" {
		if spec, ok := shebangInterpreters[trimmed]; ok {
			return spec, true
		}
	}
	return shebangSpec{}, false
}
