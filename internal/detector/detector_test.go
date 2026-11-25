package detector

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
)

func makePad(offset int, magic []byte) []byte {
	buf := make([]byte, offset+len(magic)+16)
	copy(buf[offset:], magic)
	return buf
}

func makeZIPBytes(entries map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func makePEBytes(isDLL bool) []byte {
	buf := make([]byte, 256)
	copy(buf[0:], []byte("MZ"))
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80)
	copy(buf[0x80:], []byte{'P', 'E', 0, 0})
	var chars uint16 = 0x0002
	if isDLL {
		chars |= 0x2000
	}
	binary.LittleEndian.PutUint16(buf[0x80+22:], chars)
	return buf
}

func TestDetectReader_Formats(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantName string
		wantExt  string
		matched  bool
	}{
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00}, "PNG", ".png", true},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, "JPEG", ".jpg", true},
		{"GIF89a", []byte("GIF89a\x01\x00"), "GIF", ".gif", true},
		{"WebP", []byte("RIFF\x24\x00\x00\x00WEBPVP8 "), "WebP", ".webp", true},
		{"WAV", []byte("RIFF\x24\x00\x00\x00WAVEfmt "), "WAV", ".wav", true},
		{"AVI", []byte("RIFF\x24\x00\x00\x00AVI LIST"), "AVI", ".avi", true},
		{"PDF", []byte("%PDF-1.7\n"), "PDF", ".pdf", true},
		{"GZIP", []byte{0x1F, 0x8B, 0x08, 0x00, 0x00}, "GZIP", ".gz", true},
		{"Zstd", []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00}, "Zstandard", ".zst", true},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00}, "7-Zip", ".7z", true},
		{"RAR5", []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "RAR5", ".rar", true},
		{"TAR", makePad(257, []byte("ustar")), "TAR", ".tar", true},
		{"ISO9660", makePad(32769, []byte("CD001")), "ISO 9660", ".iso", true},
		{"DICOM", makePad(128, []byte("DICM")), "DICOM", ".dcm", true},
		{"SQLite", []byte("SQLite format 3\x00\x10\x00"), "SQLite", ".sqlite", true},
		{"ELF", []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}, "ELF", ".elf", true},
		{"WASM", []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, "WebAssembly", ".wasm", true},
		{"FLAC", []byte("fLaC\x00\x00\x00\x22"), "FLAC", ".flac", true},
		{"MP3 ID3", []byte("ID3\x03\x00\x00"), "MP3", ".mp3", true},
		{"MP4 ftyp", []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 2, 0}, "MP4", ".mp4", true},
		{"HEIC ftyp", []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'h', 'e', 'i', 'c', 0, 0, 0, 0}, "HEIC", ".heic", true},
		{"AVIF ftyp", []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'a', 'v', 'i', 'f', 0, 0, 0, 0}, "AVIF", ".avif", true},
		{"MOV ftyp", []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'q', 't', ' ', ' ', 0, 0, 0, 0}, "MOV", ".mov", true},
		{"WebM EBML", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x82, 0x84, 'w', 'e', 'b', 'm'}, "WebM", ".webm", true},
		{"MKV EBML", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x82, 0x88, 'm', 'a', 't', 'r', 'o', 's', 'k', 'a'}, "MKV", ".mkv", true},
		{"Opus Ogg", append([]byte("OggS\x00\x02"), []byte("OpusHead")...), "Opus", ".opus", true},
		{"Vorbis Ogg", append([]byte("OggS\x00\x02"), []byte("\x01vorbis")...), "OGG", ".ogg", true},
		{"Java Class", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D}, "Java Class", ".class", true},
		{"Mach-O Fat", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02}, "Mach-O Fat", ".macho", true},
		{"PE EXE", makePEBytes(false), "EXE", ".exe", true},
		{"PE DLL", makePEBytes(true), "DLL", ".dll", true},
		{"DEB", []byte("!<arch>\ndebian-binary   "), "DEB", ".deb", true},
		{"DOCX", makeZIPBytes(map[string]string{"word/document.xml": "<w:document/>"}), "DOCX", ".docx", true},
		{"EPUB", makeZIPBytes(map[string]string{"mimetype": "application/epub+zip"}), "EPUB", ".epub", true},
		{"Generic ZIP", makeZIPBytes(map[string]string{"hello.txt": "world"}), "ZIP", ".zip", true},
		{"WOFF2", []byte("wOF2\x00\x01\x00\x00"), "WOFF2", ".woff2", true},
		{"AMR", []byte("#!AMR\n\x00\x01"), "AMR", ".amr", true},
		{"Shebang Python3", []byte("#!/usr/bin/env python3\nprint('hi')\n"), "Python Script", ".py", true},
		{"Shebang Bash", []byte("#!/bin/bash\necho hello\n"), "Bash Script", ".sh", true},
		{"Shebang Env -S Deno", []byte("#!/usr/bin/env -S deno run\nconsole.log(1)\n"), "TypeScript", ".ts", true},
		{"Shebang Perl5", []byte("#!/usr/bin/perl5\nprint \"hi\";\n"), "Perl Script", ".pl", true},
		{"Shebang Custom", []byte("#!/usr/local/bin/mytool\n"), "Script", "", true},
		{"JSON Object", []byte("{\n  \"name\": \"magic-bytes\",\n  \"version\": 1\n}\n"), "JSON", ".json", true},
		{"JSON Array", []byte("[1, 2, 3, \"test\"]\n"), "JSON", ".json", true},
		{"Invalid JSON", []byte("{not valid json: 123}"), "Unknown", "", false},
		{"HTML Doctype", []byte("<!DOCTYPE html>\n<html><head><title>Hi</title></head><body></body></html>"), "HTML", ".html", true},
		{"HTML Fragment", []byte("<div class=\"box\">\n  <p>Hello</p>\n</div>\n"), "HTML", ".html", true},
		{"Markdown Heading2", []byte("Intro\n\n## Section Title\nSome text here.\n"), "Markdown", ".md", true},
		{"Markdown Link", []byte("See [Wikipedia](https://en.wikipedia.org) for details.\n"), "Markdown", ".md", true},
		{"Markdown CodeFence", []byte("# Title\n\n```go\nfmt.Println(\"hi\")\n```\n"), "Markdown", ".md", true},
		{"Markdown Table", []byte("| Name | Type |\n| --- | --- |\n| PNG | Image |\n"), "Markdown", ".md", true},
		{"Plain Text Single Comment", []byte("# just a comment line\nkey=value\n"), "Unknown", "", false},
		{"Plain Text Single List", []byte("Shopping list:\n- apples\n- bananas\n"), "Unknown", "", false},
		{"Unknown Plain", []byte("just some plain text without magic bytes"), "Unknown", "", false},
		{"Empty", []byte{}, "Unknown", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := DetectReader(bytes.NewReader(tc.data), int64(len(tc.data)))
			if err != nil {
				t.Fatalf("DetectReader error: %v", err)
			}
			if res.Matched != tc.matched {
				t.Fatalf("Matched = %v, want %v (got %+v)", res.Matched, tc.matched, res)
			}
			if res.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", res.Name, tc.wantName)
			}
			if res.Extension != tc.wantExt {
				t.Errorf("Extension = %q, want %q", res.Extension, tc.wantExt)
			}
		})
	}
}
