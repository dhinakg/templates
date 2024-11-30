little_endian

proc range {from to} {
   if {$to>$from} {concat [range $from [incr to -1]] $to}
}

proc devtreeprop {} {
	section "Property" {
		#puts [format "name: 0x%x" [pos]]
		set name [ascii 32 "Name"]
		if {[string first "Unused" $name] != -1 || [string first "Reserved" $name] != -1 } {
			sectioncollapse
		}
		set len [uint32]; move -4
		set str 0
		if {$len & 0x80000000} {
			set len [expr {$len & 0xfffffff}]
			set str 1
		}
		if {$len & 0x70000000} {
			entry "Unknown flags in length" ""
		}
		entry "Length" $len 4; move 4
		
		#puts [format "val: 0x%x" [pos]]
		if {$len != 0} {
			if {!$str} {
				if {$len == 4} {
					uint32 -hex "Value"
				} elseif {$len == 8} {
					uint64 -hex "Value"
				} elseif {[string first "reg" $name] == -1} {
					ascii $len "Value"
				} else {
					bytes $len "Value"
				}
			} else {
				set fr [str $len "ascii"]
				set origpos [pos]
				move [expr {0 - $len}]
				
				if {[llength [split $fr ,]] > 1} {
					set secv "Values (placeholders)"
				} else {
					set secv "Value (placeholder)"
				}
				
				section $secv {
					sectionvalue $fr
					foreach etr [split $fr ,] {
						set nfr [split $etr /]
						if {[string match "syscfg*" $etr]} {
							section "SysCFG" { 
								entry "Name" [lindex $nfr 0] [string length [lindex $nfr 0]]
								move [expr {[string length [lindex $nfr 0]] + 1}]
								entry "SKey" [lindex $nfr 1] [string length [lindex $nfr 1]]
								move [expr {[string length [lindex $nfr 1]] + 1}]
								if {[llength $nfr] == 3} {
									entry "Length" [lindex $nfr 2] [string length [lindex $nfr 2]]
									move [string length [lindex $nfr 1]]
								}
							}
						} elseif {[string match "zeroes*" $etr]} {
							section "Zeros" {
								entry "Name" [lindex $nfr 0] [string length [lindex $nfr 0]]
								move [expr {[string length [lindex $nfr 0]] + 1}]
								entry "Zeroed Length" [lindex $nfr 1] [string length [lindex $nfr 1]]
								move [string length [lindex $nfr 1]]
							}
						} elseif {[string match "macaddr*" $etr]} {
							section "MAC Address" {
								entry "Name" [lindex $nfr 0] [string length [lindex $nfr 0]]
								move [expr {[string length [lindex $nfr 0]] + 1}]
								entry "Env Name" [lindex $nfr 1] [string length [lindex $nfr 1]]
								move [string length [lindex $nfr 1]]
							}
						} else {
							section "Unknown" {
								entry "Unknown placeholder type" [lindex $nfr 0]
							}
						}
						move 1
					}
				} 
				goto $origpos
			}
		}
		#puts [format "after: 0x%x, len: 0x%x" [pos] $len]
		move [expr {(4 - ($len & 3)) & 3}]
		#puts [format "after2: 0x%x" [pos]]
	}
}

proc devtreenode {} {
	section "Node" {
		set props [uint32 "Properties"]
		set child [uint32 "Children"]
		if {$props != 0} {
			for {set i 0} {$i < $props} {incr i} {devtreeprop}
			for {set j 0} {$j < $child} {incr j} {devtreenode}
		}
	}
}

section "Device Tree" {
	#puts "new run"
	devtreenode
}