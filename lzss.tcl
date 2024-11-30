big_endian
section "LZSS header" {
	requires 0 "63 6F 6D 70 6C 7A 73 73"
	ascii 8 "Magic"
	uint32 -hex "Adler-32"
	uint32 -hex "Decompressed data length"
	set cmplen [uint32 -hex "Compressed length"]
	uint32 -hex "Unknown"
	bytes 360 "Padding"
	entry "Compressed data" "" $cmplen
	move $cmplen
	entry "ok" "" 1
}