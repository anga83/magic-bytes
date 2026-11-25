package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"magic-bytes/internal/detector"
	"magic-bytes/internal/renamer"
)

type config struct {
	rename    bool
	recursive bool
	dryRun    bool
	target    string
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage()
		os.Exit(2)
	}

	files, err := collectFiles(cfg.target, cfg.recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	var hasErrors bool
	for _, file := range files {
		res, err := detector.DetectFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s -> Error: %v\n", file, err)
			hasErrors = true
			continue
		}

		line := formatResult(file, res)
		if !cfg.rename {
			fmt.Println(line)
			continue
		}

		plan := renamer.PlanRename(file, res)
		switch plan.Action {
		case renamer.ActionSkip:
			fmt.Printf("%s  [skipped: %s]\n", line, plan.Reason)
		case renamer.ActionUnchanged:
			fmt.Printf("%s  [unchanged]\n", line)
		case renamer.ActionAppend, renamer.ActionReplace:
			if cfg.dryRun {
				fmt.Printf("%s  [dry-run: %s -> %s]\n", line, filepath.Base(plan.OldPath), filepath.Base(plan.NewPath))
			} else {
				if err := renamer.ExecuteRename(plan); err != nil {
					fmt.Fprintf(os.Stderr, "%s  [rename error: %v]\n", line, err)
					hasErrors = true
				} else {
					fmt.Printf("%s  [renamed: %s -> %s]\n", line, filepath.Base(plan.OldPath), filepath.Base(plan.NewPath))
				}
			}
		}
	}

	if hasErrors {
		os.Exit(1)
	}
}

func parseArgs(args []string) (config, error) {
	var cfg config
	var positionals []string

	fsFlags := flag.NewFlagSet("magic-bytes", flag.ContinueOnError)
	fsFlags.BoolVar(&cfg.rename, "rename", false, "Automatically append or fix file extensions based on detected magic bytes")
	fsFlags.BoolVar(&cfg.recursive, "r", false, "Recursively analyze subdirectories")
	fsFlags.BoolVar(&cfg.recursive, "recursive", false, "Recursively analyze subdirectories")
	fsFlags.BoolVar(&cfg.dryRun, "dry-run", false, "Preview renames without modifying files")
	fsFlags.Usage = printUsage

	// Support flags both before and after the positional path argument.
	var flagArgs []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
		} else {
			positionals = append(positionals, a)
		}
	}

	if err := fsFlags.Parse(flagArgs); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return cfg, err
	}

	if len(positionals) == 0 {
		return cfg, fmt.Errorf("missing file or directory path")
	}
	if len(positionals) > 1 {
		return cfg, fmt.Errorf("expected exactly one file or directory path, got %d", len(positionals))
	}

	cfg.target = positionals[0]
	return cfg, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: magic-bytes [options] <file-or-directory>

Analyze a file or directory and detect file types using magic bytes,
independent of existing file extensions.

Options:
  --rename          Append missing or replace incorrect file extensions
  -r, --recursive   Recursively analyze subdirectories
  --dry-run         Preview --rename changes without modifying files
  -h, --help        Show this help message
`)
}

func collectFiles(target string, recursive bool) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{target}, nil
	}

	var files []string
	if !recursive {
		entries, err := os.ReadDir(target)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			full := filepath.Join(target, entry.Name())
			st, err := os.Stat(full)
			if err != nil || st.IsDir() {
				continue
			}
			files = append(files, full)
		}
		return files, nil
	}

	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			st, err := os.Stat(path)
			if err != nil || st.IsDir() {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func formatResult(path string, res detector.Result) string {
	if !res.Matched {
		return fmt.Sprintf("%s -> Unknown", path)
	}
	if res.Extension != "" {
		return fmt.Sprintf("%s -> %s (%s) [%s]", path, res.Name, res.Extension, res.MIMEType)
	}
	return fmt.Sprintf("%s -> %s [%s]", path, res.Name, res.MIMEType)
}
