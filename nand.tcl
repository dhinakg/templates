set fr [string reverse [ascii 4]]
move -4
if {$fr == "NAND" || $fr == "ATA!"} {
	entry "Device" [string reverse [ascii 4]] [move -4; format 4]; move 4
	entry "Type" [string reverse [ascii 4]] [move -4; format 4]; move 4
	uint32 -hex "ID"
	uint32 -hex "Device Offset"
	uint32 -hex "Length"
	uint32 -hex "Address"
	uint32 -hex "Entry Offset"
	uint32 -hex "Checksum"
	uint32 -hex "Version"
	uint32 -hex "Load Address"
} else {
	requires 0 "44 4E 41 4E"
}
