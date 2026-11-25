# magic-bytes

Ein schneller, abhängigkeitsfreier **Magic-Byte-Detektor** in Go, der einzelne Dateien oder ganze Verzeichnisse anhand ihrer binären Dateisignaturen (Magic Bytes) analysiert – unabhängig von der vorhandenen Dateiendung.

## Funktionen

- **Unabhängig von Dateiendungen**: Erkennt Dateitypen ausschließlich über Magic Bytes, Offsets und Container-Header.
- **Einzeldateien & Verzeichnisse**: Analysiert wahlweise eine einzelne Datei oder alle Dateien eines Verzeichnisses (optional rekursiv mit `-r` / `--recursive`).
- **Automatisches Umbenennen (`--rename`)**:
  - Fehlende Dateiendungen werden angehängt (`bild` → `bild.png`).
  - Falsche Dateiendungen werden ersetzt (`bild.txt` → `bild.png`).
  - Bereits korrekte Endungen (inkl. bekannter Aliase wie `.jpeg` für JPEG oder `.tiff` für TIFF) bleiben unverändert.
  - **Kollisionsschutz**: Existiert der Zielname bereits, wird automatisch ein Suffix (`_1`, `_2`, …) angehängt, sodass keine Dateien überschrieben werden.
- **Container-Disambiguierung**: Unterscheidet auch verschachtelte Containerformate zuverlässig, z. B.:
  - **ZIP-Container**: `DOCX`, `XLSX`, `PPTX`, `ODT`, `ODS`, `ODP`, `EPUB`, `APK`, `IPA`, `JAR`, `ZIP`
  - **RIFF-Container**: `WebP`, `WAV`, `AVI`, `ANI`
  - **ISO Base Media (`ftyp`)**: `MP4`, `MOV`, `M4A`, `M4V`, `HEIC`, `HEIF`, `AVIF`, `3GP`, `3G2`, `JP2`
  - **EBML**: `WebM`, `MKV`
  - **Ogg**: `OGG (Vorbis)`, `Opus`, `OGA (FLAC)`, `OGV (Theora)`
  - **Executables**: `PE/EXE` vs. `PE/DLL`, `Java Class` vs. `Mach-O Universal Binary (0xCAFEBABE)`
- **Shebang-Erkennung für Skripte**: Erkennt bei Textdateien automatisch Shebang-Zeilen (z. B. `#!/usr/bin/env python3`, `#!/bin/bash`, `#!/usr/bin/env -S deno run`, `#!/usr/bin/perl`) und ordnet die passende Skript-Endung (`.py`, `.sh`, `.js`, `.ts`, `.rb`, `.pl`, `.php`, `.lua`, `.ps1`, …) für `--rename` zu.
- **Keine externen Abhängigkeiten**: Nutzt ausschließlich die Go-Standardbibliothek.

---

## Installation & Build

Voraussetzung: **Go 1.24** oder neuer.

```bash
# Repository bauen
go build -o magic-bytes ./cmd/magic-bytes

# Optional global installieren
go install ./cmd/magic-bytes
```

---

## Verwendung

```text
Usage: magic-bytes [options] <file-or-directory>

Options:
  --rename          Append missing or replace incorrect file extensions
  -r, --recursive   Recursively analyze subdirectories
  --dry-run         Preview --rename changes without modifying files
  -h, --help        Show this help message
```

### Beispiele

**1. Einzelne Datei analysieren:**
```bash
./magic-bytes mystery_file
```
Ausgabe:
```text
mystery_file -> PNG (.png) [image/png]
```

**2. Verzeichnis analysieren (oberste Ebene):**
```bash
./magic-bytes ./downloads
```
Ausgabe:
```text
downloads/dokument.bin -> PDF (.pdf) [application/pdf]
downloads/foto -> JPEG (.jpg) [image/jpeg]
downloads/notizen.txt -> Unknown
```

**3. Verzeichnis rekursiv mit Vorschau (`--dry-run`) prüfen:**
```bash
./magic-bytes --rename --dry-run -r ./downloads
```
Ausgabe:
```text
downloads/dokument.bin -> PDF (.pdf) [application/pdf]  [dry-run: dokument.bin -> dokument.pdf]
downloads/foto -> JPEG (.jpg) [image/jpeg]  [dry-run: foto -> foto.jpg]
downloads/sub/clip.dat -> WebM (.webm) [video/webm]  [dry-run: clip.dat -> clip.webm]
downloads/notizen.txt -> Unknown  [skipped: unknown or extensionless type]
```

**4. Dateien automatisch umbenennen (`--rename`):**
```bash
./magic-bytes --rename ./downloads
```

---

## Unterstützte Dateiformate (Auswahl)

Die Signatur-Datenbank basiert auf der [Wikipedia List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) sowie ergänzenden Standards (IANA, libmagic, ISO BMFF):

| Kategorie | Formate |
| :--- | :--- |
| **Bilder & Grafik** | PNG, JPEG, GIF (87a/89a), WebP, BMP, TIFF, BigTIFF, Canon CR2, ICO, CUR, ANI, PSD, HEIC/HEIF, AVIF, JPEG 2000, JPEG XL, OpenEXR, ICNS, DDS, QOI, BPG, XCF, FLIF, SVG, DICOM |
| **Audio** | MP3 (ID3v2 & Frame Sync), FLAC, WAV, OGG Vorbis, Opus, OGA, AAC (ADTS), M4A, AIFF, MIDI, WMA/ASF, AMR, APE, WavPack, AU/SND |
| **Video** | MP4, M4V, MOV, AVI, MKV, WebM, FLV, SWF, MPEG-PS, MPEG-TS, 3GP, 3G2, RM/RMVB, MXF, OGV |
| **Archive & Pakete** | ZIP, GZIP, BZIP2, XZ, Zstandard, LZ4, LZMA/LZIP, 7-Zip, RAR (v4 & v5), TAR (`ustar`), CAB, ISO 9660, DEB, AR, RPM, XAR/PKG, CPIO, Unix Compress (`.Z`) |
| **Dokumente** | PDF, PostScript/EPS, RTF, DOCX, XLSX, PPTX, ODT, ODS, ODP, EPUB, MOBI/AZW, DjVu, CHM, OLE2, XML |
| **Executables & Bytecode** | ELF, PE (`.exe`/`.dll`), Mach-O (32/64/Fat), WebAssembly (`.wasm`), Java Class, JAR, APK, IPA, DEX, Lua Bytecode, LLVM Bitcode |
| **Fonts** | WOFF, WOFF2, OTF, TTF |
| **Skripte (Shebang)** | Python (`.py`), Shell/Bash (`.sh`), Zsh (`.zsh`), Fish (`.fish`), Node.js (`.js`), TypeScript/Deno (`.ts`), Ruby (`.rb`), Perl (`.pl`), PHP (`.php`), Lua (`.lua`), AWK (`.awk`), PowerShell (`.ps1`), R (`.R`), Tcl (`.tcl`), Swift (`.swift`), Groovy (`.groovy`), Scala (`.scala`) |
| **Datenbanken & Sonstiges** | SQLite 3, Apache Parquet, PCAP, PCAP-NG, HDF5, FITS, Blender (`.blend`), PGP ASCII Armor, PEM, UTF-8/UTF-16/UTF-32 BOM |

> [!NOTE]
> Reine Textdateien ohne BOM, Shebang oder eindeutigen Header (z. B. einfaches `.txt` oder `.csv`) besitzen keine binären Magic Bytes und werden bewusst als `Unknown` gemeldet (und mit `--rename` nicht verändert).

---

## Projektstruktur & Tests

```text
magic-bytes/
├── go.mod
├── cmd/magic-bytes/main.go          # CLI-Einstiegspunkt
├── internal/
│   ├── detector/
│   │   ├── detector.go              # Signatur-Engine
│   │   ├── container.go             # Container-Disambiguierung (ZIP, RIFF, ISO BMFF, EBML, Ogg, PE)
│   │   ├── shebang.go               # Shebang-Erkennung für Skript-Dateien
│   │   ├── signatures_db.go         # Magic-Byte-Datenbank
│   │   └── detector_test.go         # Unit-Tests für Formaterkennung
│   └── renamer/
│       ├── renamer.go               # Sichere Umbenennungslogik inkl. Kollisionsschutz
│       └── renamer_test.go          # Unit-Tests für Renamer
└── README.md
```

Tests ausführen:
```bash
go test -v ./...
```
