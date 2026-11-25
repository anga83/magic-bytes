package renamer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"magic-bytes/internal/detector"
)

// Action describes what PlanRename recommends for a file.
type Action int

const (
	ActionSkip Action = iota
	ActionUnchanged
	ActionAppend
	ActionReplace
)

// Plan represents a planned file rename operation.
type Plan struct {
	OldPath string
	NewPath string
	Action  Action
	Reason  string
}

// PlanRename determines whether and how a file should be renamed based on its detected type.
func PlanRename(path string, res detector.Result) Plan {
	if !res.Matched || res.Extension == "" {
		return Plan{
			OldPath: path,
			Action:  ActionSkip,
			Reason:  "unknown or extensionless type",
		}
	}

	currentExt := effectiveExt(path)
	if matchesKnownExt(currentExt, res) {
		return Plan{
			OldPath: path,
			NewPath: path,
			Action:  ActionUnchanged,
			Reason:  "extension already matches",
		}
	}

	var target string
	var action Action
	if currentExt == "" {
		action = ActionAppend
		target = path + res.Extension
	} else {
		action = ActionReplace
		rawExt := filepath.Ext(path)
		target = strings.TrimSuffix(path, rawExt) + res.Extension
	}

	target = resolveCollision(path, target, res.Extension)

	return Plan{
		OldPath: path,
		NewPath: target,
		Action:  action,
	}
}

// ExecuteRename applies a rename plan on disk.
func ExecuteRename(plan Plan) error {
	if plan.Action != ActionAppend && plan.Action != ActionReplace {
		return nil
	}
	if err := os.Rename(plan.OldPath, plan.NewPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", plan.OldPath, plan.NewPath, err)
	}
	return nil
}

// effectiveExt returns the lowercased extension, treating dotfiles like ".hidden" as having no extension.
func effectiveExt(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext == base && strings.HasPrefix(base, ".") {
		return ""
	}
	return strings.ToLower(ext)
}

func matchesKnownExt(currentExt string, res detector.Result) bool {
	if currentExt == "" {
		return false
	}
	if currentExt == strings.ToLower(res.Extension) {
		return true
	}
	for _, alias := range res.Aliases {
		if alias != "" && currentExt == strings.ToLower(alias) {
			return true
		}
	}
	return false
}

func resolveCollision(oldPath, target, ext string) string {
	if target == oldPath {
		return target
	}
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return target
	}

	stem := strings.TrimSuffix(target, ext)
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s_%d%s", stem, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}
