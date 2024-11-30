big_endian

section "Header" {
    ascii 6 "Magic"
    ascii 2 "Version"
}

goto -32
bytes 6
set offset_table_offset_size [uint8]
bytes 1
set num_objects [uint64]
bytes 8
set offset_table_offset [uint64]

proc readEmbeddedInt {} {
    set byte [uint8]
    set byte_size [expr (2 ** ($byte & 0x7))]
    if {$byte_size == 1} {
        return [list 1 $byte_size [uint8]]
    } elseif {$byte_size == 2} {
        return [list 1 $byte_size [uint16]]
    } elseif {$byte_size == 4} {
        return [list 1 $byte_size [uint32]]
    } elseif {$byte_size == 8} {
        return [list 1 $byte_size [uint64]]
    } else {
        error "Invalid embedded int size"
    }
}

proc getLength { offset } {
    # global data
    set current [pos]
    goto $offset
    set byte [uint8]
    set length 0
    set upper [expr $byte & 0xF0]
    switch $upper {
        0 {
            set length 1
        }
        16 -
        32 {
            # int or float
            set length [expr (2 ** ($byte & 0x7)) + 1]
        }
        48 {
            # date: 8 byte float
            set length 9
        }
        64 -
        80 -
        96 -
        160 -
        208 {
            # data
            if { $upper == 96 } {
                set bytes_per_char 2
            } else {
                set bytes_per_char 1
            }
            if { [expr $byte & 0x0F] != 15 } {
                set length [expr 1 + ($byte & 0x0F) * $bytes_per_char]
                # set length 1
            } else {
                set embedded_int [readEmbeddedInt]
                set length [expr 1 + [lindex $embedded_int 0] + [lindex $embedded_int 1] + [lindex $embedded_int 2] * $bytes_per_char]
            }
        }
        default {
            set length $upper
        }
    }
    goto $current
    return $length
}

proc getDataType { offset } {
    # global data
    set current [pos]
    goto $offset
    set byte [uint8]
    set result [list "Unknown" ""]
    set upper [expr $byte & 0xF0]
    switch $upper {
        0 {
            set lower [expr $byte & 0x0F]
            switch $lower {
                0 {
                    set result [list "Null" ""]
                }
                8 {
                    set result [list "Bool" "True"]
                }
                9 {
                    set result [list "Bool" "False"]
                }
                15 {
                    set result [list "Fill" ""]
                }
            }
        }
        16 {
            set result [list "Int" ""]
        }
        32 {
            set result [list "Real" ""]
        }
        48 {
            set result [list "Date" ""]
        }
        64 {
            set result [list "Data" ""]
        }
        80 {
            set result [list "String" "ASCII"]
        }
        96 {
            set result [list "String" "Unicode"]
        }
        160 {
            set result [list "Array" ""]
        }
        208 {
            set result [list "Dictionary" ""]
        }
        default {
            set result [list "Unknown" ""]
        }
    }
    goto $current
    return $result
}


goto $offset_table_offset
section "Object Table" {
    for {set i 1} {$i <= $num_objects} {incr i} {
        # hex $offset_table_offset_size "Object $i Offset"
        if {$offset_table_offset_size == 1} {
            set object_offset [uint8]
        } elseif {$offset_table_offset_size == 2} {
            set object_offset [uint16]
        } elseif {$offset_table_offset_size == 4} {
            set object_offset [uint32]
        } elseif {$offset_table_offset_size == 8} {
            set object_offset [uint64]
        } else {
            error "Invalid offset table offset size"
        }
        set object_type [getDataType $object_offset]
        set length [getLength $object_offset]
        set description ""
        if { [lindex $object_type 1] == "" } {
            set description [concat [getLength $object_offset] "bytes"]
        } else {
            set description [join [list [lindex $object_type 1] " (" [getLength $object_offset] " bytes)"] ""]
        }
        entry [lindex $object_type 0] $description [getLength $object_offset] $object_offset
    }
}


goto $offset_table_offset
section "Offset Table" {
    for {set i 1} {$i <= $num_objects} {incr i} {
        # hex $offset_table_offset_size "Object $i Offset"
        if {$offset_table_offset_size == 1} {
            set object_offset [uint8 -hex "Object $i Offset"]
        } elseif {$offset_table_offset_size == 2} {
            set object_offset [uint16 -hex "Object $i Offset"]
        } elseif {$offset_table_offset_size == 4} {
            set object_offset [uint32 -hex "Object $i Offset"]
        } elseif {$offset_table_offset_size == 8} {
            set object_offset [uint64 -hex "Object $i Offset"]
        } else {
            error "Invalid offset table offset size"
        }
    }
}

goto -32
section "Trailer" {
    # Unused
    bytes 5
    uint8 "Sort Version"
    set offset_table_offset_size [uint8 "Offset Table Offset Size"]
    uint8 "Object Ref Size"
    set num_objects [uint64 "Number of Objects"]
    uint64 -hex "Top Object Offset"
    set offset_table_offset [uint64 -hex "Offset Table Offset"]
}