little_endian

section "PMAP IO Ranges" {
	while {1} {
		set check [uint64]; move -8
		if {$check & 0xffff000000000000 != 0} {
			break
		}
		section "PMAP IO Range" {
			uint64 -hex "Address"
			uint64 -hex "Size"
			uint32 -hex "WIMG"
			entry "Name" [string reverse [ascii 4]] [move -4; format 4]; move 4
		}
	}
}