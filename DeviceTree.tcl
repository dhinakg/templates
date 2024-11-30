little_endian

set prop_name_length 32

proc dt_property {} {
    global prop_name_length
    set name [ascii $prop_name_length]
    move [expr { $prop_name_length * -1}]

    section $name {
        ascii $prop_name_length "Name"
        set prop_length [uint32 "Length"]
        # prop_length &= 0xffffff
        set prop_length [expr { $prop_length & 0xffffff }]
        if { $prop_length > 0 } {
            bytes $prop_length "Value"
        }
        if { $prop_length % 4 != 0 } {
            bytes [expr { 4 - ($prop_length % 4) }] "Padding"
        }
    }
    

}


proc dt_node {} {
    # set prop_count [uint32 "Property Count"]
    # set child_count [uint32 "Child Count"]
    set prop_count [uint32]
    set child_count [uint32]
    if { $prop_count > 0 } {
        section Properties {
            sectionvalue "$prop_count properties"
            for {set i 1} {$i <= $prop_count} {incr i} {
                dt_property
            }
        }
    }
    if { $child_count > 0 } {
        section Children {
            sectionvalue "$child_count children"
            for {set i 0} {$i < $child_count} {incr i} {
                section $i {
                    dt_node
                }
                # dt_node
            }
        }
    }
}

section "Device Tree" {
    dt_node
}