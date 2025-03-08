little_endian

proc fmtPfid {pfid} {
	return [switch -- $pfid {
		0 { format "No encryption, ECDSA Signed (%d)" $pfid }
		1 { format "Symmetric encryption (%d)" $pfid }
		105 { format "Decrypted symmetric encryption (%d)" $pfid }
		2 { format "Symmetric encryption, ECDSA Signed (%d)" $pfid }
		3 { format "ECDHE Asymmetric Encryption (%d)" $pfid }
		4 { format "ECDHE Asymmetric Encryption, ECDSA Signed (%d)" $pfid }
		5 { format "SCrypt Password-Based Encryption (%d)" $pfid }
	}]
}

proc fmtCompAlg {compalg} {
	return [switch -- $compalg {
		"-"	{ format "None (%s)" $compalg }
		"4"	{ format "LZ4 (%s)" $compalg }
		"b"	{ format "LZBITMAP (%s)" $compalg }
		"e"	{ format "LZFSE (%s)" $compalg }
		"f"	{ format "LZVN (%s)" $compalg }
		"x"	{ format "LZMA (%s)" $compalg }
		"z"	{ format "ZLIB (%s)" $compalg }
		default { format "Unknown (%s)" $compalg }
	}]
}

proc fmtChecksumAlg {csalg} {
	return [switch -- $csalg {
		"0"	{ format "None (%s)" $csalg }
		"1"	{ format "Murmur Hash (%s)" $csalg }
		"2"	{ format "SHA-256 (%s)" $csalg }
		default { format "Unknown (%s)" $csalg }
	}]
}

section "Apple Encrypted Archive" {
	requires 0 41454131
	ascii 4 "Magic"
	set pfid [uint24]; move -3
	entry "Profile ID" [fmtPfid $pfid] 3; move 3
	uint8 "SCrypt Strength"
	set as [uint32 -hex "Auth Data Size"]
	if {$as} {
		set maxpos [expr {[pos] + $as}]
		section "Auth Data" {
			set check [ascii 6]; move -6
			if {$check == "bplist"} {
				bytes $as "Auth Data Plist"
			} else {
				#assume key-value pair
				sectionname "Auth Data Dictionary"
				while {[pos] < $maxpos} {
					section "Pair" {
						set plen [uint32 -hex "Length"]
						set pmaxpos [expr {[pos] + $plen - 4}]
						cstr "ascii" "Key"
						ascii [expr {$pmaxpos - [pos]}] "Value"
					}
				}
			}
		}
	}
	if {$pfid == 0} {
		bytes 128 "ECDSA-P256 Signature"
	} elseif {$pfid == 2 || $pfid == 4} {
		bytes 160 "Header Signature"
	}
	if {$pfid == 0} {
		bytes 32 "Key Derivation Seed"
	} elseif {$pfid == 3 || $pfid == 4} {
		bytes 65 "Sender Public Key"
	}
	bytes 32 "Key Derivation Salt"
	bytes 32 "Root Header HMAC-SHA256"
	if {$pfid == 0 || $pfid == 0x69} {
		section "Root Header" {
			uint64 -hex "Original File Size"
			uint64 -hex "Encrypted Archive Size"
			set ss [uint32 -hex "Segment Size"]
			set spc [uint32 -hex "Segments per Cluster"]
			entry "Compression Algorithm" [fmtCompAlg [ascii 1]] [move -1; format 1]; move 1
			set ca [uint8]; move -1
			entry "Checksum Algorithm" [fmtChecksumAlg $ca] 1; move 1
			switch -- $ca {
				0 { set cal 0 }
				1 { set cal 8 }
				2 { set cal 32 }
			}
			set shs [expr {$cal + 8}]
			bytes 22 "Unknown"
		}
	} else {
		bytes 48 "Encrypted Root Header"
	}
	bytes 0x20 "Cluster 0 Header HMAC-SHA256"
	if {$pfid == 0 || $pfid == 0x69} {
		set j 0
		while {[pos] < [len]} {
			section -collapsed [format "Cluster %d" $j] {
				set clusterEnd 0
				set dataoff [expr {0x20 * ($spc - 1)}]
				for {set i 0} {$i < $spc} {incr i} {
					section -collapsed [format "Segment %d" $i] {
						section -collapsed [format "Segment Header" $i] {
							set osz [uint32 -hex "Original Size"]
							set csz [uint32 -hex "Compressed Size"]
							switch -- $ca {
								0 {}
								1 { uint64 -hex "Murmur Hash" }
								2 { bytes 0x20 "SHA-256" }
							}
						}
						set curpos [pos]
						move [expr {($shs * ($spc - 1 - $i)) + (0x20 * ($i + 1))}]
						bytes 32 "Segment MAC"
						move [expr {$dataoff - (0x20 * $i)}]
						if {$csz != 0} {
							if {$osz > $csz} {
								bytes $csz "Compressed Segment Data"
							} else {
								bytes $csz "Segment Data"
							}
						}
						set clusterEnd [pos]
						incr dataoff $csz
						goto $curpos
						if {$clusterEnd == [len]} {
							return -level 1
						}
					}
				}
				bytes 0x20 [format "Cluster %d Header HMAC-SHA256" [expr {$j + 1}]]
				move [expr {$dataoff + (0x20 * $spc)}]
				goto $clusterEnd
				incr j 1
			}
		}
	} else {
		bytes eof "Encrypted Clusters"
	}
}