package detector

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

func readAt(r io.ReadSeeker, offset int64, length int) ([]byte, bool) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return nil, false
	}
	buf := make([]byte, length)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return buf[:n], n > 0
}

type readerAtAdapter struct {
	r io.ReadSeeker
}

func (a readerAtAdapter) ReadAt(p []byte, off int64) (int, error) {
	if _, err := a.r.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return io.ReadFull(a.r, p)
}

func inspectZIP(r io.ReadSeeker, size int64) (Result, bool) {
	zr, err := zip.NewReader(readerAtAdapter{r: r}, size)
	if err != nil {
		return Result{}, false
	}

	var hasAndroidManifest, hasPayload, hasJarManifest bool
	for _, f := range zr.File {
		switch f.Name {
		case "mimetype":
			if rc, err := f.Open(); err == nil {
				buf, _ := io.ReadAll(io.LimitReader(rc, 256))
				rc.Close()
				mime := strings.TrimSpace(string(buf))
				switch mime {
				case "application/epub+zip":
					return Result{Name: "EPUB", Description: "Electronic Publication", Extension: ".epub", MIMEType: mime, Category: "Document", Matched: true}, true
				case "application/vnd.oasis.opendocument.text":
					return Result{Name: "ODT", Description: "OpenDocument Text", Extension: ".odt", MIMEType: mime, Category: "Document", Matched: true}, true
				case "application/vnd.oasis.opendocument.spreadsheet":
					return Result{Name: "ODS", Description: "OpenDocument Spreadsheet", Extension: ".ods", MIMEType: mime, Category: "Document", Matched: true}, true
				case "application/vnd.oasis.opendocument.presentation":
					return Result{Name: "ODP", Description: "OpenDocument Presentation", Extension: ".odp", MIMEType: mime, Category: "Document", Matched: true}, true
				}
			}
		case "word/document.xml":
			return Result{Name: "DOCX", Description: "Microsoft Word Document", Extension: ".docx", MIMEType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Category: "Document", Matched: true}, true
		case "xl/workbook.xml":
			return Result{Name: "XLSX", Description: "Microsoft Excel Spreadsheet", Extension: ".xlsx", MIMEType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Category: "Document", Matched: true}, true
		case "ppt/presentation.xml":
			return Result{Name: "PPTX", Description: "Microsoft PowerPoint Presentation", Extension: ".pptx", MIMEType: "application/vnd.openxmlformats-officedocument.presentationml.presentation", Category: "Document", Matched: true}, true
		case "AndroidManifest.xml":
			hasAndroidManifest = true
		case "META-INF/MANIFEST.MF":
			hasJarManifest = true
		default:
			if strings.HasPrefix(f.Name, "Payload/") {
				hasPayload = true
			}
		}
	}

	if hasAndroidManifest {
		return Result{Name: "APK", Description: "Android Package", Extension: ".apk", MIMEType: "application/vnd.android.package-archive", Category: "Executable", Matched: true}, true
	}
	if hasPayload {
		return Result{Name: "IPA", Description: "iOS App Store Package", Extension: ".ipa", MIMEType: "application/octet-stream", Category: "Executable", Matched: true}, true
	}
	if hasJarManifest {
		return Result{Name: "JAR", Description: "Java Archive", Extension: ".jar", MIMEType: "application/java-archive", Category: "Executable", Matched: true}, true
	}

	return Result{}, false
}

func inspectISOBMFF(r io.ReadSeeker, size int64) (Result, bool) {
	limit := 64
	if size < int64(limit) {
		limit = int(size)
	}
	buf, ok := readAt(r, 8, limit-8)
	if !ok || len(buf) < 4 {
		return Result{}, false
	}

	major := string(buf[:4])
	if res, found := matchISOBMFFBrand(major); found {
		return res, true
	}

	// Scan compatible brands starting at offset 16 (buf[8:]) if major is generic.
	for i := 8; i+4 <= len(buf); i += 4 {
		if res, found := matchISOBMFFBrand(string(buf[i : i+4])); found {
			return res, true
		}
	}

	return Result{Name: "MP4", Description: "MPEG-4 Part 14 (ISO Base Media)", Extension: ".mp4", MIMEType: "video/mp4", Category: "Video", Matched: true}, true
}

func matchISOBMFFBrand(brand string) (Result, bool) {
	switch brand {
	case "avif", "avis":
		return Result{Name: "AVIF", Description: "AV1 Image File Format", Extension: ".avif", MIMEType: "image/avif", Category: "Image", Matched: true}, true
	case "heic", "heix", "hevc", "hevx":
		return Result{Name: "HEIC", Description: "High Efficiency Image Container", Extension: ".heic", Aliases: []string{".heif"}, MIMEType: "image/heic", Category: "Image", Matched: true}, true
	case "mif1", "msf1":
		return Result{Name: "HEIF", Description: "High Efficiency Image File Format", Extension: ".heif", Aliases: []string{".heic"}, MIMEType: "image/heif", Category: "Image", Matched: true}, true
	case "qt  ":
		return Result{Name: "MOV", Description: "Apple QuickTime Movie", Extension: ".mov", MIMEType: "video/quicktime", Category: "Video", Matched: true}, true
	case "M4A ":
		return Result{Name: "M4A", Description: "MPEG-4 Audio", Extension: ".m4a", MIMEType: "audio/mp4", Category: "Audio", Matched: true}, true
	case "M4V ":
		return Result{Name: "M4V", Description: "MPEG-4 Video", Extension: ".m4v", MIMEType: "video/x-m4v", Category: "Video", Matched: true}, true
	case "3gp4", "3gp5", "3gp6", "3gp7", "3ge6", "3gg6":
		return Result{Name: "3GP", Description: "3GPP Multimedia File", Extension: ".3gp", MIMEType: "video/3gpp", Category: "Video", Matched: true}, true
	case "3g2a", "3g2b", "3g2c":
		return Result{Name: "3G2", Description: "3GPP2 Multimedia File", Extension: ".3g2", MIMEType: "video/3gpp2", Category: "Video", Matched: true}, true
	case "jp2 ":
		return Result{Name: "JP2", Description: "JPEG 2000 Image", Extension: ".jp2", MIMEType: "image/jp2", Category: "Image", Matched: true}, true
	case "mp41", "mp42", "avc1", "f4v ":
		return Result{Name: "MP4", Description: "MPEG-4 Video", Extension: ".mp4", MIMEType: "video/mp4", Category: "Video", Matched: true}, true
	default:
		return Result{}, false
	}
}

func inspectRIFF(r io.ReadSeeker, size int64) (Result, bool) {
	buf, ok := readAt(r, 8, 4)
	if !ok || len(buf) < 4 {
		return Result{}, false
	}
	switch string(buf) {
	case "WEBP":
		return Result{Name: "WebP", Description: "Google WebP Image", Extension: ".webp", MIMEType: "image/webp", Category: "Image", Matched: true}, true
	case "WAVE":
		return Result{Name: "WAV", Description: "Waveform Audio File", Extension: ".wav", MIMEType: "audio/wav", Category: "Audio", Matched: true}, true
	case "AVI ":
		return Result{Name: "AVI", Description: "Audio Video Interleave", Extension: ".avi", MIMEType: "video/x-msvideo", Category: "Video", Matched: true}, true
	case "ACON":
		return Result{Name: "ANI", Description: "Windows Animated Cursor", Extension: ".ani", MIMEType: "application/x-navi-animation", Category: "Image", Matched: true}, true
	default:
		return Result{}, false
	}
}

func inspectEBML(r io.ReadSeeker, size int64) (Result, bool) {
	limit := 4096
	if size < int64(limit) {
		limit = int(size)
	}
	buf, ok := readAt(r, 0, limit)
	if !ok {
		return Result{}, false
	}
	if bytes.Contains(buf, []byte("webm")) {
		return Result{Name: "WebM", Description: "WebM Video", Extension: ".webm", MIMEType: "video/webm", Category: "Video", Matched: true}, true
	}
	if bytes.Contains(buf, []byte("matroska")) {
		return Result{Name: "MKV", Description: "Matroska Video", Extension: ".mkv", Aliases: []string{".mka"}, MIMEType: "video/x-matroska", Category: "Video", Matched: true}, true
	}
	return Result{}, false
}

func inspectOgg(r io.ReadSeeker, size int64) (Result, bool) {
	limit := 256
	if size < int64(limit) {
		limit = int(size)
	}
	buf, ok := readAt(r, 0, limit)
	if !ok {
		return Result{}, false
	}
	switch {
	case bytes.Contains(buf, []byte("OpusHead")):
		return Result{Name: "Opus", Description: "Ogg Opus Audio", Extension: ".opus", MIMEType: "audio/opus", Category: "Audio", Matched: true}, true
	case bytes.Contains(buf, []byte("\x7fFLAC")):
		return Result{Name: "OGA", Description: "Ogg FLAC Audio", Extension: ".oga", Aliases: []string{".ogg"}, MIMEType: "audio/ogg", Category: "Audio", Matched: true}, true
	case bytes.Contains(buf, []byte("\x80theora")):
		return Result{Name: "OGV", Description: "Ogg Theora Video", Extension: ".ogv", MIMEType: "video/ogg", Category: "Video", Matched: true}, true
	case bytes.Contains(buf, []byte("\x01vorbis")):
		return Result{Name: "OGG", Description: "Ogg Vorbis Audio", Extension: ".ogg", MIMEType: "audio/ogg", Category: "Audio", Matched: true}, true
	default:
		return Result{}, false
	}
}

func inspectCafeBabe(r io.ReadSeeker, size int64) (Result, bool) {
	buf, ok := readAt(r, 4, 4)
	if !ok || len(buf) < 4 {
		return Result{}, false
	}
	val := binary.BigEndian.Uint32(buf)
	if val > 0 && val < 30 {
		return Result{Name: "Mach-O Fat", Description: "Mach-O Universal Binary", Extension: ".macho", MIMEType: "application/x-mach-binary", Category: "Executable", Matched: true}, true
	}
	return Result{Name: "Java Class", Description: "Java Compiled Class File", Extension: ".class", MIMEType: "application/java-vm", Category: "Executable", Matched: true}, true
}

func inspectPE(r io.ReadSeeker, size int64) (Result, bool) {
	if size < 0x40 {
		return Result{}, false
	}
	lfanewBuf, ok := readAt(r, 0x3C, 4)
	if !ok || len(lfanewBuf) < 4 {
		return Result{}, false
	}
	peOff := int64(binary.LittleEndian.Uint32(lfanewBuf))
	if peOff <= 0 || peOff+24 > size {
		return Result{}, false
	}
	peHeader, ok := readAt(r, peOff, 24)
	if !ok || len(peHeader) < 24 || !bytes.Equal(peHeader[:4], []byte{'P', 'E', 0, 0}) {
		return Result{}, false
	}
	characteristics := binary.LittleEndian.Uint16(peHeader[22:24])
	if characteristics&0x2000 != 0 {
		return Result{Name: "DLL", Description: "Windows Dynamic Link Library", Extension: ".dll", MIMEType: "application/vnd.microsoft.portable-executable", Category: "Executable", Matched: true}, true
	}
	return Result{Name: "EXE", Description: "Windows Portable Executable", Extension: ".exe", MIMEType: "application/vnd.microsoft.portable-executable", Category: "Executable", Matched: true}, true
}

func inspectAR(r io.ReadSeeker, size int64) (Result, bool) {
	buf, ok := readAt(r, 0, 64)
	if !ok {
		return Result{}, false
	}
	if bytes.Contains(buf, []byte("debian-binary")) {
		return Result{Name: "DEB", Description: "Debian Software Package", Extension: ".deb", MIMEType: "application/vnd.debian.binary-package", Category: "Archive", Matched: true}, true
	}
	return Result{}, false
}
