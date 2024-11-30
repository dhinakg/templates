big_endian

section "DS Store" {
	uint32 -hex "Unknown"
	ascii 4 "Magic"
	set off [uint32 -hex "Offset"]
	set sz [uint32 -hex "Size"]
	set offcheck [uint32 -hex "Offset"]
	bytes 16 "Unknown"
	if {$off != $offcheck} {
		entry "fr" "invalid val"
	} else {
		goto [expr {$off + 4}]
		section "Buddy allocator state" {
			set bc [uint32 -hex "Block count"]
			uint32 -hex "Unknown"
			for {set i 0} {$i < $bc} {incr i} {
				section -collapsed "Address" {
					set addr [uint32 -hex "Address"]
				}
			}
			bytes [expr {(256 - $bc) * 4}] "Padding"
		}
		section "Table of Contents" {
			set c [uint32 -hex "Count"]
			for {set i 0} {$i < $c} {incr i} {
				set len [uint8 -hex "Length"]
				ascii $len "Name"
				uint32 -hex "Value"
			}
		}
		section "Free list" {
			for {set j 0} {$j < 32} {incr j} {
				section "Entry" {
					entry "Key" [format 0x%x [expr {1 << $j}]]
					set flsz [uint32 -hex "Size"]
					if {$flsz != 0} {
						section "Values" {
							for {set i 0} {$i < $flsz} {incr i} {
								uint32 -hex "Element"
							}
						}
					}
				}
				if {[pos] >= [len]} { 
					break
				}
				#entry "" ""
			}
		}
	}
}