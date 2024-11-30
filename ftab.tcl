section "FTAB" {
	section "Header" {
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		bytes 8 "Unknown"
		section "Ticket" {
			set tickoff [uint32 -hex "Ticket offset"]
			set ticksize [uint32 -hex "Ticket size"]
			entry "Ticket data" "" $ticksize $tickoff
		}
		bytes 8 "Unknown"
		ascii 4 "Tag"    
		set file_magic [ascii 4 "Magic"]
		set entries [uint32 "Number of entries"]
		bytes 4
	};
	
	if {$file_magic != "ftab"} {
		#make it impossible for it to work on non-ftab
		requires 00 00
		requires 11 11
	}
	
	for {set i 0} {$i < $entries} {incr i} {
			set name [ascii 4]
			section "Tag" {
				sectionvalue $name
				set tagoff [uint32 -hex "Tag offset"]
				set tagsize [uint32 -hex "Tag size"]
				entry [format "%s data" $name] "" $tagsize $tagoff
				bytes 4
			}
	}
}