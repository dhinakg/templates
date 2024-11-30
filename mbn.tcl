little_endian

set magic [uint64]; move -8
if {$magic == 0x73D71034844BDCD1} {
	#MBN v2
	section "MBN v2 header" {
		bytes 4 "CodeWord"
		bytes 4 "Magic"
		uint32 -hex "Image Type"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		set hl [uint32 -hex "Header Size"]
		set laddr [uint32 -hex "Loading Address"]
		uint32 -hex "Body Size"
		set ds [uint32 -hex "Code Size"]
		set so [expr {[uint32 -hex "Signature Address"] - $laddr + $hl}]
		set sl [uint32 -hex "Signature Length"]
		set cso [expr {[uint32 -hex "Certificate Store Address"] - $laddr + $hl}]
		set csl [uint32 -hex "Certificate Store Length"]
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		uint32 -hex "Unknown"
		if {$ds != 0} {
			entry "Data" "" $ds
		}
		if {$sl != 0} {
			entry "Signature" "" $sl $so 
		}
		if {$csl != 0} {
			entry "Certificate Store" "" $csl $cso 
		}
	}
} elseif {$magic == 0x5548696CEA00047D} {
	# BIN
	section "BIN header" {
		bytes 8 "Magic"
		uint32 -hex "Unknown"
		uint32 -hex "Version"
		uint32 -hex "Total Size"
		uint32 -hex "Unknown"
	}
} else {
	# MBN v1 v3
	section "MBN v3 header" {
		uint32 -hex "Type"
		uint32 -hex "Version"
		uint32 -hex "Flash Address"
		set laddr [uint32 -hex "Load Address"]
		uint32 -hex "Total Length"
		set ds [uint32 -hex "Data Length"]
		set so [expr {[uint32 -hex "Signature Address"] - $laddr + 0x28}]
		set sl [uint32 -hex "Signature Length"]
		set cso [expr {[uint32 -hex "Certificate Chain Address"] - $laddr  + 0x28}]
		set csl [uint32 -hex "Certificate Chain Length"]
		if {$ds != 0} {
			entry "Data" "" $ds
		}
		if {$sl != 0} {
			entry "Signature" "" $sl $so 
		}
		if {$csl != 0} {
			entry "Certificate Store" "" $csl $cso 
		}
	}
}