little_endian

proc imd {} {
	section "Image Data" {
		set iml [uint32 -hex "Image Length"]
		bytes $iml "Image Data"
	}
}

proc unkcomp {str} {
	section [format "%s" $str] {
		uint64 -hex "Full Chapter Length"
		set cpl [uint64 -hex "Compressed Length"]
		bytes $cpl "Compressed Data"
	}
}

proc atlas {} {
	section "Atlas" {
		uint64 -hex "Full Chapter Length"
		uint64 -hex "Compressed Length"
		set imc [uint16 "Image Count"]
		bytes 2 "Padding"
		imd
	}
}

proc unk16 {} {
	uint64 -hex "Chapters Length"
	uint64 -hex "Unknown"
	section "Chapters" {
		for {set i 0} {$i < 7} {incr i} {
			section "Chapter" {
				uint64 -hex "Full Chapter Length"
				set a [uint64 -hex "Compressed Length"]
				bytes $a "Data"
			}
		}
	}
}

proc chapter_data {cpt} {
	#if {$cpt > 0xe} { return }
	section "Chapter Data" {
		switch $cpt {
			1 { unkcomp "Pack Info" }
			11 { unkcomp "0xB" }
			13 { unkcomp "0xD" }
			14 { atlas }
			15 { unkcomp "0xF" }
			16 { unk16 }
			default { entry "Unknown Data" "" }
		}
	}
}

proc chapter {} {
	section "Chapter" {
		set cpt [uint16 "Chapter ID"]
		set cho [uint64 -hex "Chapter Offset"]
		set curpos [pos]
		goto $cho
		chapter_data $cpt
		goto $curpos
	}
}

proc chapters {cha} {
	section "Chapters" {
		#for {set i 0} {$i < $cha} {incr i} {}
		for {set i 0} {$i < $cha} {incr i} {
			chapter
		}
	}
}

section "Icon Data Pack" {
	ascii 16 "Header Name"
	bytes 0x30 "Spacing"
	set cha [uint16 "Chapter Amount"]
	chapters $cha
}