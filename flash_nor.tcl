while {[ascii 4] == "hslf"} {
	move -4
	section "NOR Flash Struct" {
		entry "Magic" [string reverse [ascii 4]] [move -4; format 4]; move 4
		entry "Image Tag" [string reverse [ascii 4]] [move -4; format 4]; move 4
		uint32 -hex "Unknown"
		set adr [uint32 -hex "Address"]
		set len [uint32 -hex "Length"]
		uint32 -hex "Load Address"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
	}
}