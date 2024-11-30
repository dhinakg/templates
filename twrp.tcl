little_endian 

section "Adb Backup Stream Header" {
	ascii 8 "Magic"
	ascii 16 "Type"
	set pc [uint64 -hex "Partition Count"]
	uint64 -hex "Version"
	uint32 -hex "CRC-32"
	bytes 468 "_pad_512"
}

for {set p 0} {$p < $pc} {incr p} { 
	section "File Header" {
		ascii 8 "Magic"
		ascii 16 "Type"
		set sz [uint64 -hex "Size"]
		uint64 -hex "Compressed"
		uint32 -hex "CRC-32"
		ascii 468 "Filename"
	
		for {set i 0} {$i < $sz} {incr i 0x100000} {
			section -collapsed "Adb Backup Control Type" 
				ascii 8 "Magic"
				set mgc [ascii 16 "Type"]
				uint32 -hex "CRC-32"
				bytes 484 "_pad_512"
				#binary scan [binary format a* $mgc] H* bh
				#puts $mgc
				if {$mgc == "md5trailer"} {
					#puts [pos]
					endsection
					entry "Premature ending" [format "Needed to read 0x%x more bytes" [expr {$sz - $i}]]
					break
				} else {
					bytes 0xFFE00 "Block Of Data"
				}
			endsection
		}
	}
}