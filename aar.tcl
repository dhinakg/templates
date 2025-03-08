little_endian

proc subtype {type} {
 	return [switch -- $type {
 		0 { format "Flag" }
 		1 { format "Unsigned Integer" }
 		2 { format "String" }
 		3 { format "Hash" }
 		4 { format "Timespec" }
 		5 { format "Blob" }
 		default { format "Unknown" }
 	}]
}

proc fmtEntryType {type} {
 	return [switch -- $type {
  		"F" { format "Regular File (%s)" $type }
  		"D" { format "Directory (%s)" $type }
  		"L" { format "Symbolic Link (%s)" $type }
  		"P" { format "Fifo (%s)" $type }
  		"C" { format "Character Special (%s)" $type }
  		"B" { format "Block Special (%s)" $type }
  		"S" { format "Socket (%s)" $type }
  		"W" { format "Whiteout (%s)" $type }
  		"R" { format "Door (%s)" $type }
  		"T" { format "Port (%s)" $type }
  		"M" { format "Metadata (%s)" $type }
 		default { format "Unknown (%s)" $type }
 	}]
}

proc fmtOpType {type} {
 	return [switch -- $type {
  		"C" { format "Copy (%s)" $type }
  		"E" { format "Extract (%s)" $type }
  		"I" { format "Source Check (%s)" $type }
  		"M" { format "Manifest (%s)" $type }
  		"O" { format "Destination Fix-up (%s)" $type }
  		"P" { format "Patch (%s)" $type }
  		"R" { format "Remove (%s)" $type }
 		default { format "Unknown (%s)" $type }
 	}]
}

proc fmtTimeSpec {sec nsec} {
	return [format "%s.%d" [clock format $sec -format "%D %T"] $nsec]
}

proc fmtField {field} {
	return [switch -- $field {
		"ACL" {
            # dirs and regular files only, see AAEntryACLBlob
            format "Entry Access Control List (%s)" $field
        }
		"BTM" { 
            format "Backup Time (%s)" $field
        }
		"CKS" {
            # regular files only
            format "Entry Data 32-bit CRC (%s)" $field
        }
		"CLC" {
            # regular files only
            format "Clone Cluster ID (%s)" $field
        }
		"CTM" { 
            format "Creation Time (%s)" $field
        }
		"DAT" {
            # regular files only
            format "Entry Data (%s)" $field
        }
		"DEV" {
            # st.st_rdev, char/block devices only
            format "Device ID (%s)" $field
        }
		"DE2" {
            # from tar archives, char/block devices only
            format "Device Minor (%s)" $field
        }
		"DUZ" { 
            format "Disk Usage (%s)" $field
        }
		"FLG" {
            # st.st_flags
            format "Flags (%s)" $field
        }
		"GID" {
            # st.st_gid
            format "Group ID (%s)" $field
        }
		"GIN" {
            # from tar archives
            format "Group Name (%s)" $field
        }
		"HLC" {
            # regular files only
            format "Hard Link Cluster ID (%s)" $field
        }
		"IDX" { 
            format "Offset of entry (%s)" $field
        }
		"IDZ" { 
            format "Size of entry (%s)" $field
        }
		"INO" {
            # st.st_ino
            format "Inode number (%s)" $field
        }
		"LNK" {
            # symbolic links only
            format "Symbolic Link Path (%s)" $field
        }
		"MOD" {
            # low 12 bits of st.st_mode
            format "Access Modes (%s)" $field
        }
		"MTM" { 
            format "Modification Time (%s)" $field
        }
		"NLK" {
            # st.st_nlink from cpio archives
            format "Number of Hard Links (%s)" $field
        }
		"PAT" { 
            format "Entry Path (%s)" $field}
		"SH1" {
            # regular files only
            format "Entry Data SHA1 hash (%s)" $field
        }
		"SH2" {
            # regular files only
            format "Entry Data SHA2-256 hash (%s)" $field
        }
		"SH3" {
            # regular files only
            format "Entry Data SHA2-384 hash (%s)" $field
        }
		"SH5" {
            # regular files only
            format "Entry Data SHA2-512 hash (%s)" $field
        }
		"SIZ" {
            # regular files only
            format "Uncompressed Data size (%s)" $field
        }
		"SLC" {
            # regular files only
            format "Identical Data Cluster ID (%s)" $field
        }
		"TYP" {
            # from the high bits of st.st_mode, one of AA_ENTRY_TYPE_*
            format "Entry Type (%s)" $field
        }
		"UID" {
            # st.st_uid
            format "User ID (%s)" $field
        }
		"UIN" {
            # from tar archives
            format "User Name (%s)" $field
        }
		"XAT" {
            # see AAEntryXATBlob
            format "Entry Extended Attributes (%s)" $field
        }
		"YAF" {
            # metadata only
            format "Archived Fields (%s)" $field
        }
        "YEC" {
        	format "Error Correcting Codes (%s)" $field
        }
        "YOP" {
        	format "Operation (%s)" $field
        }
		default { 
			format "Unknown (%s)" $field
		}
	}]
}

proc handlesubtype {type field} {
 	switch -- $type {
		"*" { }
		"1" { 
			if {$field == "TYP"} {
				entry "Type" [fmtEntryType [ascii 1]] [move -1; format 1]; move 1
			} elseif {$field == "YOP"} {
				entry "Type" [fmtOpType [ascii 1]] [move -1; format 1]; move 1
			} else {
				uint8 -hex "Value"
			}
		}
		"2" { 
			if {$field == "MOD"} {
				entry "Octal Mode" [format "%o" [uint16]] [move -2; format 2]; move 2
			} else {
				uint16 -hex "Value"
			}
		}
		"4" { uint32 -hex "Value" }
		"8" { uint64 -hex "Value" }
		"A" { 
			set len [uint16 -hex "Length"]
			bytes $len "Data"
		}
		"B" { 
			set len [uint32 -hex "Length"]
			bytes $len "Data"
		}
		"C" { 
			set len [uint64 -hex "Length"]
			bytes $len "Data"
		}
		"F" { bytes 4 "Hash" }
		"G" { bytes 20 "Hash" }
		"H" { bytes 32 "Hash" }
		"I" { bytes 48 "Hash" }
		"J" { bytes 64 "Hash" }
		"S" { unixtime64 "Timespec" }
		"T" { 
			set tv_sec [int64]
			set tv_nsec [int32]; move -12
			entry "Timestamp" [fmtTimeSpec $tv_sec $tv_nsec] 12; move 12
		 }
		"P" { 
			set slen [uint16 -hex "String Length"]
			if {$slen != 0} {
				ascii $slen "String"
			}
		}
		default { return -level 2 }
 	}
}


proc fieldname {name} {
	return [switch -- $type {
 		"TYP" { format "Type" }
 		default { format "Unknown" }
 	}]
}

proc aar {} {
	set i 0
	section "Apple Archive" {
		while {[pos] < [len] && $i < 3000} {
		#for {set i 0} {$i < 2} {incr i} { }
			section "Header" {
				requires [pos] 41413031
				ascii 4 "Magic"
				set hs [uint16 -hex "Header Size"]
				set maxpos [expr {[pos] - 6 + $hs}]
				section "Fields" {
					while {[pos] < $maxpos} {
						section {} {
							set type [ascii 3]; move -3
							entry "Name" [fmtField $type] 3; move 3
							sectionname $type
							set stype [ascii 1 "Subtype"]
							handlesubtype $stype $type
						}
					}
				}
			}
			incr i
		}
		if {$i == 3000} {
			entry "Results truncated for performance" "Anchor the template here for more results" 4
		}
	}
}
aar