package detector

// signaturesDB contains magic byte definitions derived from Wikipedia's
// "List of file signatures" and supplementary standards (IANA, libmagic, ISO BMFF).
var signaturesDB = []Signature{
	// =========================================================================
	// IMAGES & GRAPHICS
	// =========================================================================
	{
		Name: "PNG", Description: "Portable Network Graphics", Extension: ".png", MIMEType: "image/png", Category: "Image", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}}},
	},
	{
		Name: "JPEG", Description: "JPEG Image", Extension: ".jpg", Aliases: []string{".jpeg", ".jpe", ".jfif"}, MIMEType: "image/jpeg", Category: "Image", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xD8, 0xFF}}},
	},
	{
		Name: "GIF", Description: "Graphics Interchange Format (87a)", Extension: ".gif", MIMEType: "image/gif", Category: "Image", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte("GIF87a")}},
	},
	{
		Name: "GIF", Description: "Graphics Interchange Format (89a)", Extension: ".gif", MIMEType: "image/gif", Category: "Image", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte("GIF89a")}},
	},
	{
		Name: "TIFF", Description: "Tagged Image File Format (Little-Endian)", Extension: ".tif", Aliases: []string{".tiff"}, MIMEType: "image/tiff", Category: "Image", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x49, 0x49, 0x2A, 0x00}}},
	},
	{
		Name: "TIFF", Description: "Tagged Image File Format (Big-Endian)", Extension: ".tif", Aliases: []string{".tiff"}, MIMEType: "image/tiff", Category: "Image", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x4D, 0x4D, 0x00, 0x2A}}},
	},
	{
		Name: "BigTIFF", Description: "BigTIFF Image", Extension: ".btf", Aliases: []string{".tif", ".tiff"}, MIMEType: "image/tiff", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x49, 0x49, 0x2B, 0x00}}},
	},
	{
		Name: "Canon CR2", Description: "Canon Raw 2 Image", Extension: ".cr2", MIMEType: "image/x-canon-cr2", Category: "Image", Priority: 100,
		Patterns: []Pattern{
			{Offset: 0, Value: []byte{0x49, 0x49, 0x2A, 0x00}},
			{Offset: 8, Value: []byte("CR\x02\x00")},
		},
	},
	{
		Name: "BMP", Description: "Windows Bitmap", Extension: ".bmp", Aliases: []string{".dib"}, MIMEType: "image/bmp", Category: "Image", Priority: 60,
		Patterns: []Pattern{{Offset: 0, Value: []byte("BM")}},
	},
	{
		Name: "ICO", Description: "Windows Icon", Extension: ".ico", MIMEType: "image/x-icon", Category: "Image", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0x01, 0x00}}},
	},
	{
		Name: "CUR", Description: "Windows Cursor", Extension: ".cur", MIMEType: "image/x-icon", Category: "Image", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0x02, 0x00}}},
	},
	{
		Name: "PSD", Description: "Adobe Photoshop Document", Extension: ".psd", MIMEType: "image/vnd.adobe.photoshop", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("8BPS")}},
	},
	{
		Name: "JPEG XL", Description: "JPEG XL Image (Codestream)", Extension: ".jxl", MIMEType: "image/jxl", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0x0A}}},
	},
	{
		Name: "JPEG XL", Description: "JPEG XL Image (Container)", Extension: ".jxl", MIMEType: "image/jxl", Category: "Image", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A}}},
	},
	{
		Name: "JPEG 2000", Description: "JPEG 2000 Image", Extension: ".jp2", Aliases: []string{".j2k"}, MIMEType: "image/jp2", Category: "Image", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}}},
	},
	{
		Name: "OpenEXR", Description: "OpenEXR High Dynamic Range Image", Extension: ".exr", MIMEType: "image/x-exr", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x76, 0x2F, 0x31, 0x01}}},
	},
	{
		Name: "ICNS", Description: "Apple Icon Image", Extension: ".icns", MIMEType: "image/icns", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("icns")}},
	},
	{
		Name: "DDS", Description: "DirectDraw Surface", Extension: ".dds", MIMEType: "image/vnd.ms-dds", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("DDS ")}},
	},
	{
		Name: "QOI", Description: "Quite OK Image", Extension: ".qoi", MIMEType: "image/qoi", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("qoif")}},
	},
	{
		Name: "BPG", Description: "Better Portable Graphics", Extension: ".bpg", MIMEType: "image/bpg", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x42, 0x50, 0x47, 0xFB}}},
	},
	{
		Name: "XCF", Description: "GIMP Image", Extension: ".xcf", MIMEType: "image/x-xcf", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("gimp xcf ")}},
	},
	{
		Name: "FLIF", Description: "Free Lossless Image Format", Extension: ".flif", MIMEType: "image/flif", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("FLIF")}},
	},
	{
		Name: "SVG", Description: "Scalable Vector Graphics", Extension: ".svg", MIMEType: "image/svg+xml", Category: "Image", Priority: 40,
		Patterns: []Pattern{{Offset: 0, Value: []byte("<svg")}},
	},

	// =========================================================================
	// CONTAINERS (RIFF, ISO BMFF, EBML, OGG, ZIP, OLE2)
	// =========================================================================
	{
		Name: "RIFF", Description: "Resource Interchange File Format", Extension: ".riff", MIMEType: "application/octet-stream", Category: "Container", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte("RIFF")}},
		Inspect:  inspectRIFF,
	},
	{
		Name: "ISO BMFF", Description: "ISO Base Media File", Extension: ".mp4", MIMEType: "video/mp4", Category: "Video", Priority: 85,
		Patterns: []Pattern{{Offset: 4, Value: []byte("ftyp")}},
		Inspect:  inspectISOBMFF,
	},
	{
		Name: "EBML", Description: "Extensible Binary Meta Language", Extension: ".mkv", MIMEType: "video/x-matroska", Category: "Video", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x1A, 0x45, 0xDF, 0xA3}}},
		Inspect:  inspectEBML,
	},
	{
		Name: "OGG", Description: "Ogg Multimedia Container", Extension: ".ogg", MIMEType: "application/ogg", Category: "Audio", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte("OggS")}},
		Inspect:  inspectOgg,
	},
	{
		Name: "ZIP", Description: "ZIP Archive", Extension: ".zip", MIMEType: "application/zip", Category: "Archive", Priority: 80,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x50, 0x4B, 0x03, 0x04}}},
		Inspect:  inspectZIP,
	},
	{
		Name: "ZIP (Empty)", Description: "Empty ZIP Archive", Extension: ".zip", MIMEType: "application/zip", Category: "Archive", Priority: 80,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x50, 0x4B, 0x05, 0x06}}},
	},
	{
		Name: "ZIP (Spanned)", Description: "Spanned ZIP Archive", Extension: ".zip", MIMEType: "application/zip", Category: "Archive", Priority: 80,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x50, 0x4B, 0x07, 0x08}}},
	},
	{
		Name: "OLE2", Description: "Microsoft Compound File Binary (DOC/XLS/PPT)", Extension: ".ole2", Aliases: []string{".doc", ".xls", ".ppt", ".msg", ".msi"}, MIMEType: "application/x-ole-storage", Category: "Document", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}}},
	},

	// =========================================================================
	// AUDIO
	// =========================================================================
	{
		Name: "MP3", Description: "MPEG Audio Layer III (ID3v2)", Extension: ".mp3", MIMEType: "audio/mpeg", Category: "Audio", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("ID3")}},
	},
	{
		Name: "MP3", Description: "MPEG Audio Layer III (Frame Sync)", Extension: ".mp3", MIMEType: "audio/mpeg", Category: "Audio", Priority: 55,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xFB}}},
	},
	{
		Name: "MP3", Description: "MPEG-2 Audio Layer III (Frame Sync)", Extension: ".mp3", MIMEType: "audio/mpeg", Category: "Audio", Priority: 55,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xF3}}},
	},
	{
		Name: "MP3", Description: "MPEG-2.5 Audio Layer III (Frame Sync)", Extension: ".mp3", MIMEType: "audio/mpeg", Category: "Audio", Priority: 55,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xF2}}},
	},
	{
		Name: "AAC", Description: "Advanced Audio Coding (ADTS)", Extension: ".aac", MIMEType: "audio/aac", Category: "Audio", Priority: 55,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xF1}}},
	},
	{
		Name: "AAC", Description: "Advanced Audio Coding (MPEG-2 ADTS)", Extension: ".aac", MIMEType: "audio/aac", Category: "Audio", Priority: 55,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xF9}}},
	},
	{
		Name: "FLAC", Description: "Free Lossless Audio Codec", Extension: ".flac", MIMEType: "audio/flac", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("fLaC")}},
	},
	{
		Name: "AIFF", Description: "Audio Interchange File Format", Extension: ".aiff", Aliases: []string{".aif", ".aifc"}, MIMEType: "audio/aiff", Category: "Audio", Priority: 90,
		Patterns: []Pattern{
			{Offset: 0, Value: []byte("FORM")},
			{Offset: 8, Value: []byte("AIFF")},
		},
	},
	{
		Name: "MIDI", Description: "Musical Instrument Digital Interface", Extension: ".mid", Aliases: []string{".midi"}, MIMEType: "audio/midi", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("MThd")}},
	},
	{
		Name: "ASF/WMA/WMV", Description: "Advanced Systems Format", Extension: ".asf", Aliases: []string{".wma", ".wmv"}, MIMEType: "video/x-ms-asf", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C}}},
	},
	{
		Name: "AMR", Description: "Adaptive Multi-Rate Audio", Extension: ".amr", MIMEType: "audio/amr", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("#!AMR\n")}},
	},
	{
		Name: "APE", Description: "Monkey's Audio", Extension: ".ape", MIMEType: "audio/x-ape", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("MAC ")}},
	},
	{
		Name: "WavPack", Description: "WavPack Lossless Audio", Extension: ".wv", MIMEType: "audio/x-wavpack", Category: "Audio", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("wvpk")}},
	},
	{
		Name: "AU", Description: "Sun/NeXT Audio File", Extension: ".au", Aliases: []string{".snd"}, MIMEType: "audio/basic", Category: "Audio", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte(".snd")}},
	},

	// =========================================================================
	// VIDEO
	// =========================================================================
	{
		Name: "FLV", Description: "Flash Video", Extension: ".flv", MIMEType: "video/x-flv", Category: "Video", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("FLV\x01")}},
	},
	{
		Name: "SWF", Description: "Adobe Flash (Uncompressed)", Extension: ".swf", MIMEType: "application/x-shockwave-flash", Category: "Video", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("FWS")}},
	},
	{
		Name: "SWF", Description: "Adobe Flash (Zlib Compressed)", Extension: ".swf", MIMEType: "application/x-shockwave-flash", Category: "Video", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("CWS")}},
	},
	{
		Name: "SWF", Description: "Adobe Flash (LZMA Compressed)", Extension: ".swf", MIMEType: "application/x-shockwave-flash", Category: "Video", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("ZWS")}},
	},
	{
		Name: "MPEG-PS", Description: "MPEG Program Stream", Extension: ".mpg", Aliases: []string{".mpeg", ".vob"}, MIMEType: "video/mpeg", Category: "Video", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0x01, 0xBA}}},
	},
	{
		Name: "MPEG-TS", Description: "MPEG Transport Stream", Extension: ".ts", Aliases: []string{".m2ts"}, MIMEType: "video/mp2t", Category: "Video", Priority: 50,
		Patterns: []Pattern{
			{Offset: 0, Value: []byte{0x47}},
			{Offset: 188, Value: []byte{0x47}},
			{Offset: 376, Value: []byte{0x47}},
		},
	},
	{
		Name: "RM", Description: "RealMedia Video", Extension: ".rm", Aliases: []string{".rmvb"}, MIMEType: "application/vnd.rn-realmedia", Category: "Video", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte(".RMF")}},
	},
	{
		Name: "MXF", Description: "Material Exchange Format", Extension: ".mxf", MIMEType: "application/mxf", Category: "Video", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x06, 0x0E, 0x2B, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0D, 0x01, 0x02, 0x01, 0x01, 0x02}}},
	},

	// =========================================================================
	// ARCHIVES & COMPRESSION
	// =========================================================================
	{
		Name: "GZIP", Description: "GZIP Compressed Archive", Extension: ".gz", Aliases: []string{".tgz"}, MIMEType: "application/gzip", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x1F, 0x8B, 0x08}}},
	},
	{
		Name: "BZIP2", Description: "BZIP2 Compressed Archive", Extension: ".bz2", MIMEType: "application/x-bzip2", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("BZh")}},
	},
	{
		Name: "XZ", Description: "XZ Compressed Archive", Extension: ".xz", MIMEType: "application/x-xz", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}}},
	},
	{
		Name: "Zstandard", Description: "Zstandard Compressed File", Extension: ".zst", MIMEType: "application/zstd", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x28, 0xB5, 0x2F, 0xFD}}},
	},
	{
		Name: "LZ4", Description: "LZ4 Frame Format", Extension: ".lz4", MIMEType: "application/x-lz4", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x04, 0x22, 0x4D, 0x18}}},
	},
	{
		Name: "LZMA", Description: "Lempel-Ziv-Markov Chain Algorithm", Extension: ".lz", MIMEType: "application/x-lzip", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("LZIP")}},
	},
	{
		Name: "7-Zip", Description: "7-Zip Archive", Extension: ".7z", MIMEType: "application/x-7z-compressed", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}}},
	},
	{
		Name: "RAR5", Description: "RAR Archive (v5.0+)", Extension: ".rar", MIMEType: "application/vnd.rar", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}}},
	},
	{
		Name: "RAR", Description: "RAR Archive (v1.5–v4.x)", Extension: ".rar", MIMEType: "application/vnd.rar", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}}},
	},
	{
		Name: "TAR", Description: "POSIX TAR Archive", Extension: ".tar", MIMEType: "application/x-tar", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 257, Value: []byte("ustar")}},
	},
	{
		Name: "CAB", Description: "Microsoft Cabinet Archive", Extension: ".cab", MIMEType: "application/vnd.ms-cab-compressed", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("MSCF")}},
	},
	{
		Name: "ISO 9660", Description: "ISO 9660 CD/DVD Image", Extension: ".iso", MIMEType: "application/x-iso9660-image", Category: "Archive", Priority: 85,
		Patterns: []Pattern{{Offset: 32769, Value: []byte("CD001")}},
	},
	{
		Name: "ISO 9660", Description: "ISO 9660 CD/DVD Image (Alt Offset)", Extension: ".iso", MIMEType: "application/x-iso9660-image", Category: "Archive", Priority: 85,
		Patterns: []Pattern{{Offset: 34817, Value: []byte("CD001")}},
	},
	{
		Name: "AR", Description: "Unix Archive / Static Library", Extension: ".a", Aliases: []string{".ar", ".deb"}, MIMEType: "application/x-archive", Category: "Archive", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("!<arch>\n")}},
		Inspect:  inspectAR,
	},
	{
		Name: "RPM", Description: "Red Hat Package Manager", Extension: ".rpm", MIMEType: "application/x-rpm", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xED, 0xAB, 0xEE, 0xDB}}},
	},
	{
		Name: "XAR", Description: "eXtensible ARchive / macOS PKG", Extension: ".xar", Aliases: []string{".pkg"}, MIMEType: "application/x-xar", Category: "Archive", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("xar!")}},
	},
	{
		Name: "CPIO", Description: "CPIO Archive (ASCII)", Extension: ".cpio", MIMEType: "application/x-cpio", Category: "Archive", Priority: 85,
		Patterns: []Pattern{{Offset: 0, Value: []byte("070701")}},
	},
	{
		Name: "Unix Compress", Description: "Unix Compress (.Z)", Extension: ".Z", MIMEType: "application/x-compress", Category: "Archive", Priority: 80,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x1F, 0x9D}}},
	},

	// =========================================================================
	// DOCUMENTS
	// =========================================================================
	{
		Name: "PDF", Description: "Portable Document Format", Extension: ".pdf", MIMEType: "application/pdf", Category: "Document", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("%PDF-")}},
	},
	{
		Name: "PostScript", Description: "PostScript Document", Extension: ".ps", Aliases: []string{".eps"}, MIMEType: "application/postscript", Category: "Document", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("%!PS-Adobe-")}},
	},
	{
		Name: "RTF", Description: "Rich Text Format", Extension: ".rtf", MIMEType: "application/rtf", Category: "Document", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("{\\rtf")}},
	},
	{
		Name: "DjVu", Description: "DjVu Document", Extension: ".djvu", MIMEType: "image/vnd.djvu", Category: "Document", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("AT&TFORM")}},
	},
	{
		Name: "CHM", Description: "Microsoft Compiled HTML Help", Extension: ".chm", MIMEType: "application/vnd.ms-htmlhelp", Category: "Document", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("ITSF\x03\x00\x00\x00")}},
	},
	{
		Name: "MOBI", Description: "Mobipocket eBook", Extension: ".mobi", Aliases: []string{".azw"}, MIMEType: "application/x-mobipocket-ebook", Category: "Document", Priority: 95,
		Patterns: []Pattern{{Offset: 60, Value: []byte("BOOKMOBI")}},
	},
	{
		Name: "XML", Description: "Extensible Markup Language", Extension: ".xml", Aliases: []string{".svg", ".plist", ".xhtml"}, MIMEType: "application/xml", Category: "Document", Priority: 35,
		Patterns: []Pattern{{Offset: 0, Value: []byte("<?xml ")}},
	},

	// =========================================================================
	// EXECUTABLES, OBJECTS & BYTECODE
	// =========================================================================
	{
		Name: "ELF", Description: "Executable and Linkable Format", Extension: ".elf", Aliases: []string{".so", ".o", ""}, MIMEType: "application/x-elf", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x7F, 'E', 'L', 'F'}}},
	},
	{
		Name: "PE/MZ", Description: "DOS/Windows Executable", Extension: ".exe", Aliases: []string{".dll", ".sys"}, MIMEType: "application/vnd.microsoft.portable-executable", Category: "Executable", Priority: 70,
		Patterns: []Pattern{{Offset: 0, Value: []byte("MZ")}},
		Inspect:  inspectPE,
	},
	{
		Name: "Mach-O 64-bit", Description: "Mach-O 64-bit Binary (LE)", Extension: ".macho", Aliases: []string{".dylib", ".o"}, MIMEType: "application/x-mach-binary", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xCF, 0xFA, 0xED, 0xFE}}},
	},
	{
		Name: "Mach-O 64-bit", Description: "Mach-O 64-bit Binary (BE)", Extension: ".macho", Aliases: []string{".dylib"}, MIMEType: "application/x-mach-binary", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFE, 0xED, 0xFA, 0xCF}}},
	},
	{
		Name: "Mach-O 32-bit", Description: "Mach-O 32-bit Binary (LE)", Extension: ".macho", Aliases: []string{".dylib"}, MIMEType: "application/x-mach-binary", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xCE, 0xFA, 0xED, 0xFE}}},
	},
	{
		Name: "Mach-O 32-bit", Description: "Mach-O 32-bit Binary (BE)", Extension: ".macho", Aliases: []string{".dylib"}, MIMEType: "application/x-mach-binary", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFE, 0xED, 0xFA, 0xCE}}},
	},
	{
		Name: "Java Class / Mach-O Fat", Description: "Java Class or Mach-O Universal Binary", Extension: ".class", MIMEType: "application/java-vm", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xCA, 0xFE, 0xBA, 0xBE}}},
		Inspect:  inspectCafeBabe,
	},
	{
		Name: "WebAssembly", Description: "WebAssembly Binary", Extension: ".wasm", MIMEType: "application/wasm", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 'a', 's', 'm'}}},
	},
	{
		Name: "DEX", Description: "Dalvik Executable", Extension: ".dex", MIMEType: "application/vnd.android.dex", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("dex\n03")}},
	},
	{
		Name: "Lua Bytecode", Description: "Lua Compiled Bytecode", Extension: ".luac", MIMEType: "application/x-lua-bytecode", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x1B, 'L', 'u', 'a'}}},
	},
	{
		Name: "LLVM Bitcode", Description: "LLVM Bitcode Wrapper", Extension: ".bc", MIMEType: "application/x-llvm", Category: "Executable", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("BC\xC0\xDE")}},
	},

	// =========================================================================
	// FONTS
	// =========================================================================
	{
		Name: "WOFF", Description: "Web Open Font Format", Extension: ".woff", MIMEType: "font/woff", Category: "Font", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("wOFF")}},
	},
	{
		Name: "WOFF2", Description: "Web Open Font Format 2", Extension: ".woff2", MIMEType: "font/woff2", Category: "Font", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("wOF2")}},
	},
	{
		Name: "OTF", Description: "OpenType Font", Extension: ".otf", MIMEType: "font/otf", Category: "Font", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("OTTO")}},
	},
	{
		Name: "TTF", Description: "TrueType Font", Extension: ".ttf", MIMEType: "font/ttf", Category: "Font", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x01, 0x00, 0x00, 0x00}}},
	},

	// =========================================================================
	// DATABASES, SCIENTIFIC, NETWORK & MISC
	// =========================================================================
	{
		Name: "SQLite", Description: "SQLite 3 Database", Extension: ".sqlite", Aliases: []string{".sqlite3", ".db"}, MIMEType: "application/vnd.sqlite3", Category: "Database", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte("SQLite format 3\x00")}},
	},
	{
		Name: "Parquet", Description: "Apache Parquet Columnar Storage", Extension: ".parquet", MIMEType: "application/vnd.apache.parquet", Category: "Database", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("PAR1")}},
	},
	{
		Name: "PCAP", Description: "Libpcap Packet Capture (LE)", Extension: ".pcap", MIMEType: "application/vnd.tcpdump.pcap", Category: "Network", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xD4, 0xC3, 0xB2, 0xA1}}},
	},
	{
		Name: "PCAP", Description: "Libpcap Packet Capture (BE)", Extension: ".pcap", MIMEType: "application/vnd.tcpdump.pcap", Category: "Network", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xA1, 0xB2, 0xC3, 0xD4}}},
	},
	{
		Name: "PCAPNG", Description: "PCAP Next Generation Capture", Extension: ".pcapng", MIMEType: "application/x-pcapng", Category: "Network", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x0A, 0x0D, 0x0D, 0x0A}}},
	},
	{
		Name: "HDF5", Description: "Hierarchical Data Format 5", Extension: ".h5", Aliases: []string{".hdf5"}, MIMEType: "application/x-hdf5", Category: "Database", Priority: 100,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1A, '\n'}}},
	},
	{
		Name: "FITS", Description: "Flexible Image Transport System", Extension: ".fits", Aliases: []string{".fit"}, MIMEType: "application/fits", Category: "Database", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("SIMPLE  = ")}},
	},
	{
		Name: "DICOM", Description: "Digital Imaging and Communications in Medicine", Extension: ".dcm", MIMEType: "application/dicom", Category: "Image", Priority: 95,
		Patterns: []Pattern{{Offset: 128, Value: []byte("DICM")}},
	},
	{
		Name: "Blender", Description: "Blender 3D Project", Extension: ".blend", MIMEType: "application/x-blender", Category: "Misc", Priority: 95,
		Patterns: []Pattern{{Offset: 0, Value: []byte("BLENDER")}},
	},
	{
		Name: "PGP", Description: "Pretty Good Privacy ASCII Armor", Extension: ".asc", Aliases: []string{".pgp", ".gpg"}, MIMEType: "application/pgp-encrypted", Category: "Security", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("-----BEGIN PGP ")}},
	},
	{
		Name: "PEM", Description: "Privacy-Enhanced Mail Certificate/Key", Extension: ".pem", Aliases: []string{".crt", ".key"}, MIMEType: "application/x-pem-file", Category: "Security", Priority: 90,
		Patterns: []Pattern{{Offset: 0, Value: []byte("-----BEGIN ")}},
	},
	{
		Name: "UTF-8 BOM", Description: "UTF-8 Text with Byte Order Mark", Extension: ".txt", MIMEType: "text/plain; charset=utf-8", Category: "Text", Priority: 20,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xEF, 0xBB, 0xBF}}},
	},
	{
		Name: "UTF-32 LE BOM", Description: "UTF-32 Little-Endian Text", Extension: ".txt", MIMEType: "text/plain; charset=utf-32le", Category: "Text", Priority: 25,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xFE, 0x00, 0x00}}},
	},
	{
		Name: "UTF-32 BE BOM", Description: "UTF-32 Big-Endian Text", Extension: ".txt", MIMEType: "text/plain; charset=utf-32be", Category: "Text", Priority: 25,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0x00, 0x00, 0xFE, 0xFF}}},
	},
	{
		Name: "UTF-16 LE BOM", Description: "UTF-16 Little-Endian Text", Extension: ".txt", MIMEType: "text/plain; charset=utf-16le", Category: "Text", Priority: 20,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFF, 0xFE}}},
	},
	{
		Name: "UTF-16 BE BOM", Description: "UTF-16 Big-Endian Text", Extension: ".txt", MIMEType: "text/plain; charset=utf-16be", Category: "Text", Priority: 20,
		Patterns: []Pattern{{Offset: 0, Value: []byte{0xFE, 0xFF}}},
	},
}
