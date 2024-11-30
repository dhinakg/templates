little_endian

proc srcVersion {{compact 0}} {
	set srcv [uint64 -hex]; move -8
	#packed as:
	#	a: 24 bits
	#	b: 10 bits
	#	c: 10 bits
	#	d: 10 bits
	#	e: 10 bits
    set a [expr {$srcv >> 40}]
    set b [expr {($srcv >> 30) & 0x3ff}]
    set c [expr {($srcv >> 20) & 0x3ff}]
    set d [expr {($srcv >> 10) & 0x3ff}]
    set e [expr {$srcv & 0x3ff}]
    if {$compact} {
    	entry "Compact Version" [format "%d.%d.%d.%d.%d" $a $b $c $d $e] 8; move 8\
    } else {
    	entry "Source Version" [format "%d.%d.%d.%d.%d" $a $b $c $d $e] 8; move 8
    }
    return $a
}; #end proc

proc appflags {} {
	set value [uint32]; move -4
    entry "Flags" [
        if {$value != 0} {
            #", " at end of each so there's always a trailing ", " i can remove
            if {$value & (1<<0)} {append opt "Shared Library, "}
            if {$value & (1<<1)} {append opt "Prebound, "}
            format "%s (0x%X)" [string range $opt 0 end-2] $value
        } else {
            format "No flags (%d)" 0
        }
    ] 4; move 4
}

proc magicstr {num} {
	return [binary format I* $num]
}

proc crc32 {pos sz exp} {
	package require crc32
	set curpos [pos]
	goto $pos
	set calc [crc::crc32 [bytes $sz]]
	goto $curpos
	if {$calc == $exp} {
		entry "Correct CRC32" ""
	} else {
		entry "Incorrect CRC32; expected 0x%X)" ""
	}
}

proc sepromba {baoff} {
	section "SEPROM Boot Args" {
	     set sepbmgc [uint32]
	     if {$sepbmgc == 0} {
	     	sectioncollapse
	     }
	     entry "Magic" [magicstr $sepbmgc] 4 [expr {[pos]-4}]
	     move 4; #Reserved
	     uint32 -hex "Version"
	     move 4; #Reserved
	     uint32 -hex "Size"
	     move 4; #Reserved
	     uint64 -hex "TZ Start"
	     uint32 -hex "TZ Size"
	     move 4; #Reserved
	     entry "Payload Tag" [magicstr [uint32]] 4 [expr {[pos]-4}]
	     move 4; #Reserved
	     uint8 -hex "Manifest Hash Valid"
	     move 7; #Reserved
	     bytes 48 "Manifest Hash"
	     uint8 -hex "Verify Manifest Hash"
	     move 7; #Reserved
	     uint32 -hex "Manifest Offset"
	     move 4; #Reserved     
	     uint32 -hex "Manifest Bytes/Size"
	     move 4; #Reserved
	     bytes 64 "Entropy"        
	}; #end seprom bootargs
	set curpos [pos]
	if {$baoff == 0} {
		set baoff [expr {$curpos + 32}]
	}
	for {set i 0} {[pos] + 16 <= $baoff} {incr i} {
	    section "Memory Map" {
	        set basecheck [uint64 -hex "Base"]
	        if {$basecheck == 0} {
	        	sectioncollapse
	        }
	        uint64 -hex "Size"
	    }
	}
}


goto 1024
if {[uint32] == 1} {
	move -1028
	entry "Boot Instructions" "" 1024; move 1024;
	section "Legion Version" {
    	set ver [uint32 -hex "Subversion"]
    	set baoff [uint32 -hex "SEPOS Boot Args Offset"]
    	ascii 16 "Legion String"
    	move 2; #Reserved
	}; #end section
} else {
	move -1028
	entry "Boot Instructions" "" 2048; move 2048; #sizeof(uint64) * 256
	entry "Boot Vectors" "" 2048; move 2048;
	set check [uint32]; move -4
    if {$check == 0x808} {
    	uint64 -hex "UUID Offset"
    	section "Astris UUID" {
    		ascii 4 "Magic"
    		uint32 -hex "Version"
    		uint32 -hex "RTXC Version"
    		uint32 -hex "Client Version"
    		uuid "UUID"
    		uint32 -hex "Slide"
    		bytes 12 "Reserved"
    	}
    }
	section "Legion Version" {
    	set ver [uint32 -hex "Subversion"]
    	ascii 16 "Legion String"
    	set baoff [uint16 -hex "SEPOS Boot Args Offset"]
    	bytes 2 "Reserved"
	}; #end section
}

if {$ver == 4} {
	section "Legion64 Boot Arg Fields" {
		sepromba $baoff
		if {$baoff != 0} {
	    	goto $baoff
	    }
	    section "SEPOS BootArgs" {
	        set noway [uuid "Kernel UUID"]
	        uint64 -hex "Kernel Heap Size"
	        set ks [uint64 -hex "Kernel RO Start"]
	        set ke [uint64 -hex "Kernel RO End"]
	        entry "Kernel RO" "" [expr {$ke - $ks}] $ks
	        section "Kernel RO" {
	        	set cpos [pos]
	        	goto $ks
	        	include "Executables/Mach-O.tcl"
	        	goto $cpos
	        }
	        set as [uint64 -hex "App RO Start"]
	        set ae [uint64 -hex "App RO End"]
	        entry "App RO" "" [expr {$ae - $as}] $as
	        uint64 -hex "End of Payload"
	        uint64 -hex "Minimum TZ0 size"
	        #SHM = "Shared Memory Entry"
	        if {$noway != "D69C60C7-4C5E-C732-942E-C82EABBD5009" && $noway != "C5648CC5-4789-F93D-A7BA-222BC35624A1"} {
	        	uint64 -hex "Minimum TZ1 size"
	        	uint64 -hex "Minimum AR Plaintext size"
	        	uint64 -hex "Minimum Non-AR Plaintext size"
	        }
	        uint64 -hex "SHM Base"
	        uint64 -hex "SHM Size"
	        section "Rootserver info" {
	            set pb [uint64 -hex "Physical Base"]
	            uint64 -hex "Virtual Base"
	            set vs [uint64 -hex "Virtual Size"]
	            entry "Physical RO" "" $vs $pb
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Physical Base"
	            uint64 -hex "Stack Virtual Base"
	            uint64 -hex "Stack Size"
	            uint64 -hex "Normal Memory Size"
	            uint64 -hex "Non AR Memory Size"; #AR meaning Anti-Replay
	            uint64 -hex "Heap Memory Size"
	            uint64 -hex "Virtual Memory Size"
	            uint64 -hex "DART Memory Size"
	            uint64 -hex "Thread Count"
	            uint64 -hex "CNode Count"
	            ascii 16 "Name"
	            uuid "UUID" 
	            set major [srcVersion]
	        }; #end rootserver
	        set expcrc [uint32 -hex "SEPOS CRC-32"]
	        set try [uint32]
	        if {$try == 0} {
	        	uint8 -hex "Coredump supported"
	        	bytes 3 "Padding"
	        }
	    }; #end bootargs
	    if {$try != 0} {
	    	#bytes 0x100 "Unknown"
	    	move -4
	    	uint32 -hex "Kernel Non-AR Memory"
	    	section "Dynamic Objects" {
	    		set flag 0
	    		for {set i 0} {$i < 16} {incr i} {
	    				section "Dynamic Object" {
	    					set a [uint32 -hex "Handle"]
	    					set b [uint32 -hex "SEP Offset"]
	    					set c [uint32 -hex "DART Offset"]
	    					set d [uint32 -hex "SEP Size"]
	    					if {$a || $b || $c || $d} {
	    						incr flag
	    					} else {
	    						sectioncollapse
	    					}
	    				}
	    		}
	    		if {$flag == 0} {
	    			sectioncollapse
	    		}
	    	}
		}
		set numapps [uint32 "Number of Apps"]
	    set numshlib [uint32 "Number of shared libs"]
	    if {$numapps > 69} {set numapps 15}
	    
	    for {set i 0} {$i < $numapps} {incr i} {
	        section "App List Entry" {
	            set pbro [uint64 -hex "Physical Base RO"]
	            set psro [uint64 -hex "Physical Size RO"]
	            entry "Physical RO" "" $psro $pbro
	            set pbrw [uint64 -hex "Physical Base RW"]
	            set psrw [uint64 -hex "Physical Size RW"]
	            entry "Physical RW" "" $psrw $pbrw
	            uint64 -hex "Virtual Base"
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Size"
	            uint64 -hex "Normal Memory Size"
	            uint64 -hex "Non AR Memory Size"
	            uint64 -hex "Heap Memory Size"
	            uint64 -hex "Virtual Memory Size"
	            uint64 -hex "DART Memory Size"
	            uint64 -hex "Thread Count"
	            uint64 -hex "CNode Count"
	            set compatv [uint32]; move -4
	            if {$compatv != 0xFFFFFFFF} {
	                srcVersion 1
	            } else {
	                entry "Compact Version" "App Not Versioned" 8; move 8
	            }
	            ascii 16 "Name"
	            uuid "UUID" 
	            srcVersion
	            if {$major > 1700} {
	            	appflags
	            }
	        }; #end section
	    }; #end for 
	    for {set i 0} {$i < $numshlib} {incr i} {
	        section "Shared Library Entry" {
	            set pbro [uint64 -hex "Physical Base RO"]
	            set psro [uint64 -hex "Physical Size RO"]
	            entry "Physical RO" "" $psro $pbro
	            set pbrw [uint64 -hex "Physical Base RW"]
	            set psrw [uint64 -hex "Physical Size RW"]
	            entry "Physical RW" "" $psrw $pbrw
	            uint64 -hex "Virtual Base"
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Size"
	            uint64 -hex "Normal Memory Size"
	            uint64 -hex "Non AR Memory Size"
	            uint64 -hex "Heap Memory Size"
	            uint64 -hex "Virtual Memory Size"
	            uint64 -hex "DART Memory Size"
	            uint64 -hex "Thread Count"
	            uint64 -hex "CNode Count"
	            set compatv [uint32]; move -4
	            if {$compatv != 0xFFFFFFFF} {
	                srcVersion 1
	            } else {
	                entry "Compact Version" "App Not Versioned" 8; move 8
	            }
	            ascii 16 "Name"
	            uuid "UUID" 
	            srcVersion
	            if {$major > 1700} {
	            	appflags
	            }
	        }; #end section
	    }; #end for 
	}; #end legion64
} elseif {$ver == 3} {
	section "Legion64 Boot Arg Fields" {
	    sepromba $baoff
	    if {$baoff != 0} {
	    	goto $baoff
	    }
	    
	    section "SEPOS BootArgs" {
	        set noway [uuid "Kernel UUID"]
	        uint64 -hex "Kernel Heap Size"
	        uint64 -hex "Kernel RO Start"
	        uint64 -hex "Kernel RO End"
	        uint64 -hex "App RO Start"
	        uint64 -hex "App RO End"
	        uint64 -hex "End of Payload"
	        uint64 -hex "Minimum TZ0 size"
	        #SHM = "Shared Memory Entry"
	        if {$noway != "EE9C6047-0D8D-8332-96C4-9AF44DB84FFE" && $noway != "7A965EF6-EDA3-EE36-8B15-BF619189F4DE" && $noway != "D69C60C7-4C5E-C732-942E-C82EABBD5009" && $noway != "C5648CC5-4789-F93D-A7BA-222BC35624A1" && $noway != "12B14326-2A48-A637-8043-A7C9DEEAB4AC"} {
	        	uint64 -hex "Minimum TZ1 size"
	        	uint64 -hex "Minimum AR Plaintext size"
	        	uint64 -hex "Minimum Non-AR Plaintext size"
	        }
	        uint64 -hex "SHM Base"
	        uint64 -hex "SHM Size"
	        section "Rootserver info" {
	            uint64 -hex "Physical Base"
	            uint64 -hex "Virtual Base"
	            uint64 -hex "Virtual Size"
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Physical Base"
	            uint64 -hex "Stack Virtual Base"
	            uint64 -hex "Stack Size"
	            if {$noway != "7A965EF6-EDA3-EE36-8B15-BF619189F4DE" && $noway != "EE9C6047-0D8D-8332-96C4-9AF44DB84FFE"} {
	            	uint64 -hex "Normal Memory Size"
	            	uint64 -hex "Non AR Memory Size"; #AR meaning Anti-Replay
	            	uint64 -hex "Heap Memory Size"
	            } 
	            ascii 16 "Name"
	            uuid "UUID" 
	            if {$noway != "7A965EF6-EDA3-EE36-8B15-BF619189F4DE" && $noway != "EE9C6047-0D8D-8332-96C4-9AF44DB84FFE" && $noway != "C22B4BDF-CF1D-C832-AC60-B7E4E72AEC7C"} {
	            	set major [srcVersion]
	            } else {
	            	set major 0
	            }
	        }; #end rootserver
	        uint32 -hex "SEPOS CRC-32"
	        uint8 -hex "Coredump supported"
	        bytes 3 "Padding"
	    }; #end bootargs
	    set numapps [uint32 "Number of Apps"]
	    uint32 "Number of Shared Libraries"
	    if {$numapps > 69} {set numapps 15}
	    
	    for {set i 0} {$i < $numapps} {incr i} {
	        section "App List Entry" {
	            uint64 -hex "Physical Base RO"
	            uint64 -hex "Physical Size RO"
	            uint64 -hex "Physical Base RW"
	            uint64 -hex "Physical Size RW"
	            uint64 -hex "Virtual Base"
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Size"
	            if {$noway != "7A965EF6-EDA3-EE36-8B15-BF619189F4DE" && $noway != "EE9C6047-0D8D-8332-96C4-9AF44DB84FFE" && $noway != "C22B4BDF-CF1D-C832-AC60-B7E4E72AEC7C"} {
	            	uint64 -hex "Normal Memory Size"
	            	uint64 -hex "Non AR Memory Size"
	            	uint64 -hex "Heap Memory Size"
	            }
	            set compatv [uint32]; move -4
	            if {$compatv != 0xFFFFFFFF} {
	                srcVersion 1
	            } else {
	                entry "Compact Version" "App Not Versioned" 8; move 8
	            }
	            ascii 16 "Name"
	            uuid "UUID" 
	            if {$noway != "7A965EF6-EDA3-EE36-8B15-BF619189F4DE" && $noway != "EE9C6047-0D8D-8332-96C4-9AF44DB84FFE" && $noway != "C22B4BDF-CF1D-C832-AC60-B7E4E72AEC7C"} {
	            	srcVersion
	            }
	            if {$major > 1700} {
	            	appflags
	            }
	        }; #end section
	    }; #end for 
	}; #end legion64
} elseif {$ver == 2} {
	section "Legion64 Boot Arg Fields" {
	    sepromba $baoff
	    if {$baoff != 0} {
	    	goto $baoff
	    }
	    
	    section "SEPOS BootArgs" {
	        set noway [uuid "Kernel UUID"]
	        uint64 -hex "Kernel RO Start"
	        uint64 -hex "End of Payload"
	        uint64 -hex "App RO Start"
	        uint64 -hex "App RO End"
	        uint64 -hex "Unknown"
	        section "Rootserver info" {
	            uint64 -hex "Physical Base"
	            uint64 -hex "Virtual Base"
	            uint64 -hex "Virtual Size"
	            uint64 -hex "Virtual Entry"
	            uint64 -hex "Stack Physical Base"
	            uint64 -hex "Stack Virtual Base"
	            uint64 -hex "Stack Size"
	            ascii 16 "Name"
	            uuid "UUID" 
	        }; #end rootserver
	        uint32 -hex "SEPOS CRC-32"
	        uint8 -hex "Coredump supported"
	        bytes 3 "Padding"
	    }; #end bootargs
	    set numapps [uint32 "Number of Apps"]
	    uint32 "Number of shared libs"
	    if {$numapps > 69} {set numapps 15}
	    
	    for {set i 0} {$i < $numapps} {incr i} {
	        section "App List Entry" {
	            uint64 -hex "Physical Address"
	        	uint64 -hex "Virtual Base"
	        	uint64 -hex "Size"
	        	uint64 -hex "Entry"
	        	uint64 -hex "Stack Size"
	            set compatv [uint32]; move -4
	            if {$compatv != 0xFFFFFFFF} {
	                srcVersion 1
	            } else {
	                entry "Compact Version" "App Not Versioned" 8; move 8
	            }
	            uint64 -hex "Unknown"
	            ascii 16 "Name"
	            uuid "UUID" 
	        }; #end section
	    }; #end for 
	}; #end legion64
} elseif {$ver == 1} {
	goto $baoff
	section "Monitor Boot Args" {
		#monitor related
		section "Monitor" {
    		uint32 -hex "Version"
    		uint32 -hex "Virtual base"
    		uint32 -hex "Physical base"
    		uint32 -hex "Memory size"
    	}
    	#kernel related
    	section "Kernel" {
    		set off [uint32 -hex "Boot-args offset"]
    		uint32 -hex "Entry"
    		#uint32 -hex "Physical base"
    		#uint32 -hex "Physical slide"
    		#uint32 -hex "Virtual slide"
    		uuid "UUID"
    	}
	}
	goto $off
	section "Kernel Boot Args" {
		uint16 -hex "Version"
		uint16 -hex "Revision"
		#bytes 12 "Unknown"
		#set idk [uint32 "Unknown/Version"]
		#bytes 24 "Unknown"
		#uint32 -hex "CRC-32"
		#bytes 8 "Unknown"
		##check to see if this is the new or old
		##	Firmware magic string
		##	Without which, what are these bits?
		##	SEP denied.
		#set check [uint8]; move -1
		#bytes 256 "Unused"
		
		uint32 -hex "virtBase"            
		# Virtual base of memory */
		uint32 -hex "physBase"            
		# Physical base of memory */
		uint32 -hex "memSize"             
		# Size of memory */
		set idk [uint32 -hex "topOfKernelData"]     
		# Highest physical address used in kernel data area */
		uint64 -hex "sharedMemBase"       
		# Base physical address of the panic buffer */
		uint32 -hex "sharedMemSize"       
		# Size of the panic buffer in bytes */
		bytes 12 "_reserved"              
		# reserved and unused */
		uint32 -hex "sepos_crc32"         
		# crc32 of sepos apps */
		uint32 -hex "seprom_args_offset"  
		# offset of seprom args, filled in by l4 */
		uint32 -hex "seprom_phys_offset"  
		# seprom phys offset, filled in by l4 */
		bytes 16 "entropy"           
		# Early boot entropy */
		set numapp [uint32 -hex "num_apps"]            
		# number of apps */
		uint32 -hex "num_shlibs"          
		# number of shared libs */
		bytes 232 "_unused"
		
		if {$idk == 1267} {
			#ios 11 a10
			set idk 690
		}
		
		if {$idk < 1000} {
			#is the new one
			if {$idk < 525 || $idk >= 827 || $idk == 794} { 
				#is probably 64-bit struct, idk
				section "Kernel App Info" {
					uint64 -hex "Physical Base RO"
	        		uint64 -hex "Physical Size RO"
	        		uint64 -hex "Physical Base RW"
	        		uint64 -hex "Physical Size RW"
	        		uint64 -hex "Virtual Base"
	        		uint64 -hex "Virtual Entry"
	        		uint64 -hex "Stack Size"
	        		uint64 -hex "Normal Memory Size"
	        		uint64 -hex "Non AR Memory Size"
	        		uint64 -hex "Heap Memory Size"
	        		bytes 32 "Unknown"
	        		set compatv [uint32]; move -4
	        		if {$compatv != 0xFFFFFFFF} {
	        		    uint32 -hex "Compact Version Start" 
	        		    uint32 -hex "Compact Version End" 
	        		} else {
	        		    entry "Compact Version" "App Not Versioned" 8; move 8
	        		}
	        		ascii 16 "Name"
	        		uuid "UUID" 
	        		set major [srcVersion]
	        		if {$major > 1700} {
	        	    	bytes 4 "Unknown"
	        	    }
	        	}
	        	if {$numapp > 255 || $numapp == 0} {set numapp 12}
				for {set i 0} {$i < $numapp} {incr i} {
					section "App Info" {
						uint64 -hex "Physical Base RO"
	        	    	uint64 -hex "Physical Size RO"
	        	    	uint64 -hex "Physical Base RW"
	        	    	uint64 -hex "Physical Size RW"
	        	    	uint64 -hex "Virtual Base"
	        	    	uint64 -hex "Virtual Entry"
	        	    	uint64 -hex "Stack Size"
	        	    	uint64 -hex "Normal Memory Size"
	        	    	uint64 -hex "Non AR Memory Size"
	        	    	uint64 -hex "Heap Memory Size"
	        	    	bytes 32 "Unknown"
	        	    	set compatv [uint32]; move -4
	        	    	if {$compatv != 0xFFFFFFFF} {
	        	    	    uint32 -hex "Compact Version Start" 
	        	    	    uint32 -hex "Compact Version End" 
	        	    	} else {
	        	    	    entry "Compact Version" "App Not Versioned" 8; move 8
	        	    	}
	        	    	ascii 16 "Name"
	        	    	uuid "UUID" 
	        	    	srcVersion
	        	    	if {$major > 1700} {
	        	    		uint32 -hex "Flags"
	        	    	}
	        	    }
	    		}
	    	} else {
	    		#is prob 32-bit struct, idk
				for {set i 0} {$i < 11} {incr i} {
					section "App Info" {
						uint64 -hex "Physical Address"
	        	    	uint32 -hex "Virtual Base"
	        	    	uint32 -hex "Size"
	        	    	uint32 -hex "Entry"
	        	    	uint32 -hex "Stack Size"
	        	    	if {$idk >= 700} {
	        	    		uint32 -hex "Normal Memory Size"
	        	    		uint32 -hex "Non AR Memory Size"
	        	    	}
	        	    	if {$idk > 712} {
	        	    		uint32 -hex "Heap Memory Size"
	        	    	}
	        	    	set compatv [uint32]; move -4
	        	    	if {$compatv != 0xFFFFFFFF} {
	        	    	    uint32 -hex "Compact Version Start" 
	        	    	    uint32 -hex "Compact Version End" 
	        	    	} else {
	        	    	    entry "Compact Version" "App Not Versioned" 8; move 8
	        	    	}
	        	    	ascii 12 "Name"
	        	    	uuid "UUID" 
	        	    	#srcVersion
	        	    }
	    		}
	    	}
		} else {
			#old version
			for {set i 0} {$i < 12} {incr i} {
				section "App Info" {
					uint64 -hex "Physical Base"
					uint32 -hex "Virtual Base"
					uint32 -hex "Size"
					uint32 -hex "Entry"
					ascii 12 "Name"
					uuid "UUID"
				}
			}
		}
	}
}