big_endian

section "Header" {
    ascii 6 "Magic"
    ascii 2 "Version"
}

goto -32
bytes 6
set offset_table_offset_size [uint8]
set object_ref_size [uint8]
set num_objects [uint64]
bytes 8
set offset_table_offset [uint64]

proc readEmbeddedInt {suppress} {
	if {$suppress} {
		set byte [uint8]
    	set byte_size [expr (2 ** ($byte & 0x7))]
    	set value [switch $byte_size {
    		1 { uint8 }
    		2 { uint16 }
    		4 { uint32 }
    		8 { uint64 }
    		default { error "Invalid embedded int size" }
    	}]
    	
	} else {
		section -collapsed "Data Size" {
    		set byte [uint8]; move -1
    		set byte_size [expr (2 ** ($byte & 0x7))]
    		entry "Size" $byte_size 1; move 1
    		set value [switch $byte_size {
    			1 { uint8 -hex "Value" }
    			2 { uint16 -hex "Value" }
    			4 { uint32 -hex "Value" }
    			8 { uint64 -hex "Value" }
    			default { error "Invalid embedded int size" }
    		}]
    		sectionvalue [format "0x%X" $value]
    	}
    }
    return [list 1 $byte_size $value]
}

proc getLength { offset full } {
    # global data
    global object_ref_size
    goto $offset
    set byte [uint8]
    set length 0
    set upper [expr {($byte & 0xF0) >> 0x4}]
    set lower [expr $byte & 0x0F]
    set toAdd [expr $full ? 1 : 0]
    switch [format "0x%X" $upper] {
        0x0 {
        	# null, bool, fill
            set length $toAdd
        }
        0x1 -
    	0x2 {
            # int or real
            set length [expr (2 ** ($byte & 0x7) + $toAdd)]
        }
        0x3 {
            # date: 8 byte float
            set length [expr 8 + $toAdd]
        }
        0x4 -
        0x5 -
        0x6 -
        0xA -
        0xD {
            # string, data
            if { $upper == 0x6 } {
                set bytes_per_char 2
            } elseif {$upper == 0xA || $upper == 0xD} {
            	set bytes_per_char $object_ref_size
            } else {
                set bytes_per_char 1
            }
            if { $lower != 15 } {
                set length [expr $toAdd + $lower * $bytes_per_char]
                # set length 1
            } elseif {$full} {
            	set embedded_int [readEmbeddedInt 1]
            	set length [expr $toAdd + [lindex $embedded_int 0] + [lindex $embedded_int 1] + [lindex $embedded_int 2] * $bytes_per_char]
            } else {
                set length [expr [lindex [readEmbeddedInt 0] 2] * $bytes_per_char]
            }
        }
        default {
            set length [expr $upper << 4]
        }
    }
    return $length
}

proc getDataType { offset suppress } {
    # global data
    set current [pos]
    goto $offset
    set byte [uint8]; move -1
    set result [list "Unknown" ""]
    set upper [expr {($byte & 0xF0) >> 0x4}]
    set lower [expr {$byte & 0x0F}]
    switch [format "0x%X" $upper] {
        0x0 {
            switch $lower {
                0x0 {
                    set result [list "Null" "" 0]
                }
                0x8 {
                    set result [list "Bool" "True" 0]
                }
                0x9 {
                    set result [list "Bool" "False" 0]
                }
                0xF {
                    set result [list "Fill" "" 0]
                }
            }
        }
        0x1 {
            set result [list "Int" "" 0]
        }
        0x2 {
            set result [list "Real" "" 0]
        }
        0x3 {
            set result [list "Date" "" 0]
        }
        0x4 {
            set result [list "Data" "" 0]
        }
        0x5 {
            set result [list "ASCII String" "" 0]
        }
        0x6 {
            set result [list "Unicode String" "" 0]
        }
        0xA {
            set result [list "Array" "" 1]
        }
        0xD {
            set result [list "Dictionary" "" 2]
        }
        default {
            set result [list "Unknown" "" 0]
        }
    }
    if {!$suppress} {
    	section -collapsed "Info" {
    		entry "Type" [concat [lindex $result 0] [format "(0x%X)" $upper]] 1
    		sectionvalue [lindex $result 0]
    		if {$upper == 0} {
    			entry "Value" [lindex $result 1] 1
    		} elseif {$lower == 0xF} {
    			entry "Length" "Next field (0xF)" 1
    		} else {
    			entry "Length" [format "0x%X" $lower] 1
    		}
    	}; move 1
    }
    goto $current
    return $result
}


goto $offset_table_offset
section "Object Table" {
    for {set i 1} {$i <= $num_objects} {incr i} {
    	section "Object $i" {
    		set object_offset [switch $offset_table_offset_size {
    			1 { uint8 }
    			2 { uint16 }
    			4 { uint32 }
    			8 { uint64 }
    			default { error "Invalid offset table offset size" }
    		}]
    		set curpos [pos]
        	set object_type [getDataType $object_offset 0]
        	set length [getLength $object_offset 0]
        	if { [lindex $object_type 1] == "" } {
        	    set description ""
        	} else {
        	    set description [lindex $object_type 1]
        	}
        	set comp_type [lindex $object_type 2]
        	if {$comp_type == 1 || $comp_type == 2} {
        		if {$comp_type == 2} {
        			section "Keys" {
        				for {set j 1} {$j <= $length / $object_ref_size} {incr j} {
        					set eo [switch $object_ref_size {
    							1 { uint8 }
    							2 { uint16 }
    							4 { uint32 }
    							8 { uint64 }
    							default { error "Invalid offset table offset size" }
    						}]
							set cpos [pos]
							goto [expr {$offset_table_offset + $eo * $offset_table_offset_size}]
							set oo [switch $offset_table_offset_size {
    							1 { uint8 }
    							2 { uint16 }
    							4 { uint32 }
    							8 { uint64 }
    							default { error "Invalid offset table offset size" }
    						}]
    						entry "Key Object" "" [getLength $oo 1] $oo
							goto $cpos
        				}
        			}
        		}
        		section "Entries" {
        			for {set j 1} {$j <= $length / $object_ref_size} {incr j} {
        				set eo [switch $object_ref_size {
    						1 { uint8 }
    						2 { uint16 }
    						4 { uint32 }
    						8 { uint64 }
    						default { error "Invalid offset table offset size" }
    					}]
						set cpos [pos]
						goto [expr {$offset_table_offset + $eo * $offset_table_offset_size}]
						set oo [switch $offset_table_offset_size {
    						1 { uint8 }
    						2 { uint16 }
    						4 { uint32 }
    						8 { uint64 }
    						default { error "Invalid offset table offset size" }
    					}]
    					entry "Entry Object" [lindex [getDataType $oo 1] 0] [getLength $oo 1] $oo
						goto $cpos
        			}
        		}
        	} else {
        		entry "Value" $description $length
        	}
        	goto $curpos
        }
    }
}


goto $offset_table_offset
section "Offset Table" {
    for {set i 1} {$i <= $num_objects} {incr i} {
		set object_offset [switch $offset_table_offset_size {
    		1 { uint8 -hex "Object $i Offset" }
    		2 { uint16 -hex "Object $i Offset" }
    		4 { uint32 -hex "Object $i Offset" }
    		8 { uint64 -hex "Object $i Offset" }
    		default { error "Invalid offset table offset size" }
    	}]
    }
}

goto -32
section "Trailer" {
    bytes 5 "Reserved"
    uint8 "Sort Version"
    uint8 -hex "Offset Table Offset Size"
    uint8 -hex "Object Ref Size"
    uint64 "Number of Objects"
    uint64 -hex "Top Object Offset"
    uint64 -hex "Offset Table Offset"
}