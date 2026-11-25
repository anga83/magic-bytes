package renamer

import (
	"os"
	"path/filepath"
	"testing"

	"magic-bytes/internal/detector"
)

func TestPlanRename_And_Execute(t *testing.T) {
	dir := t.TempDir()

	pngRes := detector.Result{
		Name:      "PNG",
		Extension: ".png",
		Matched:   true,
	}
	jpgRes := detector.Result{
		Name:      "JPEG",
		Extension: ".jpg",
		Aliases:   []string{".jpeg", ".jpe"},
		Matched:   true,
	}

	// 1. No extension -> append
	noExt := filepath.Join(dir, "image_no_ext")
	if err := os.WriteFile(noExt, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := PlanRename(noExt, pngRes)
	if plan.Action != ActionAppend || plan.NewPath != noExt+".png" {
		t.Fatalf("unexpected append plan: %+v", plan)
	}
	if err := ExecuteRename(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(noExt + ".png"); err != nil {
		t.Fatalf("expected renamed file %s.png: %v", noExt, err)
	}

	// 2. Wrong extension -> replace
	wrongExt := filepath.Join(dir, "photo.txt")
	if err := os.WriteFile(wrongExt, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan = PlanRename(wrongExt, jpgRes)
	if plan.Action != ActionReplace || plan.NewPath != filepath.Join(dir, "photo.jpg") {
		t.Fatalf("unexpected replace plan: %+v", plan)
	}

	// 3. Alias extension (.jpeg) -> unchanged
	aliasExt := filepath.Join(dir, "photo.jpeg")
	if err := os.WriteFile(aliasExt, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan = PlanRename(aliasExt, jpgRes)
	if plan.Action != ActionUnchanged {
		t.Fatalf("expected ActionUnchanged for alias .jpeg, got %+v", plan)
	}

	// 4. Collision -> _1 suffix
	existing := filepath.Join(dir, "dup.png")
	if err := os.WriteFile(existing, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	dupWrong := filepath.Join(dir, "dup.bin")
	if err := os.WriteFile(dupWrong, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan = PlanRename(dupWrong, pngRes)
	if plan.Action != ActionReplace || plan.NewPath != filepath.Join(dir, "dup_1.png") {
		t.Fatalf("expected collision-safe dup_1.png, got %+v", plan)
	}

	// 5. Dotfile without extension -> append instead of stripping filename
	dotfile := filepath.Join(dir, ".secret")
	if err := os.WriteFile(dotfile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan = PlanRename(dotfile, pngRes)
	if plan.Action != ActionAppend || plan.NewPath != dotfile+".png" {
		t.Fatalf("expected dotfile append .secret.png, got %+v", plan)
	}

	// 6. Unknown -> skip
	plan = PlanRename(dotfile, detector.UnknownResult())
	if plan.Action != ActionSkip {
		t.Fatalf("expected ActionSkip for Unknown, got %+v", plan)
	}
}
