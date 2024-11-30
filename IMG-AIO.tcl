little_endian

set magic [bytes 4]; move -4
if {$magic == "8900" || $magic == "8740" || $magic == "8720" || $magic == "8730" || $magic == "8702" || $magic == "8723" || $magic == "8740" || $magic == "8442" || $magic == "8443"} {
    proc formatType {label magic} {
        set value [uint8]
        move -1
        set name [switch -- $value {
            1 { format "Boot encrypted with UID-key"}
            2 { format "Boot plaintext"}
            3 { format "Encrypted with Key"}
            4 { format "Plaintext"}
            default {format "Unknown Format (%d)" $value}
        }]
        if {$value == 3 && $magic == "8900"} {
        	set name "Encrypted with Key 0x837"
        }
        entry $label $name 1
    }
    
    section "S5L8900 Header" {
    	ascii 4 "Platform"
        if {$magic == "8740" || $magic == "8723"} {
        	set mov 0x400
        } elseif {$magic == "8720" || $magic == "8730"} {
        	set mov 0x600
        } else {
        	set mov 0x800
        }
        ascii 0x3 "Version"
        formatType "Format" $magic
        move 1
        uint32 -hex "Entry"
        set datasz [uint32 -hex "Data size"]
        #These are relative to the end of the header
        set sigoff [uint32 -hex "Footer signature offset"]
        if {$sigoff + $mov >= [len]} {
        	set sigoff $datasz
        }
        set certoff [uint32 -hex "Footer certificate offset"]
        set siglen 0x80
        set certlen [uint32 -hex "Footer certificate length"]
        bytes 0x20 "Salt"
        uint16 -hex "Unknown2"
        uint16 -hex "Security epoch"
        bytes 0x10 "Header signature"
        bytes 4 "Unencrypted signature"
        entry "Padding" "" [expr {$mov - 84}]; move [expr {$mov - 84}]
        entry "Data" "" $datasz
    }
}

set magic1 [bytes 4]; move -4
if {$magic1 == "2gmI"} {
    set extheader 0
    proc opts {label} {
        set value [uint32]; move -4
        entry $label [
            if {$value != 0} {
                #", " at end of each so there's always a trailing ", " i can remove
                if {$value & (1<<0)} {append opt "External Signature, "}
                if {$value & (1<<1)} {append opt "SHA1 in Signature Data, "}
                if {$value & (1<<2)} {append opt "CRC32 in Signature Data, "}
                if {$value & (1<<8)} {append opt "Trusted Image, "}
                if {$value & (1<<9)} {append opt "Encrypted Image, "}
                if {$value & (1<<24)} {append opt "Image with Secure Boot, "}
                if {$value & (1<<30)} {append opt "With extension header, "; set ::extheader 1}
                if {$value & (1<<31)} {append opt "Immutable, "}
                format [string range $opt 0 end-2]
            } else {
                format "No Options"
            }
        ] 4; move 4
    }
    
    section "IMG2 Header" {
        entry "Magic" [string reverse [ascii 4]] [move -4; format 4]; move 4
        entry "Image Type" [string reverse [ascii 4]] [move -4; format 4]; move 4
    	uint16 -hex "Revision"
    	uint16 -hex "Security epoch"
    	uint32 -hex "Load Address"
    	set datsz [uint32 -hex "Data Size"]
    	uint32 -hex "Decrypted Data Size"
    	uint32 -hex "Allocation Size"
    	opts "Options"
    	bytes 0x40 "Signature Data"
    	set extsize [uint32 -hex "Next Extension Size"]
    	uint32 -hex "Header CRC32"
    }
    
    if {$extheader == 1} {
        section "IMG2 Header Extension" {
            uint32 -hex "Fields CRC32"
            uint32 -hex "Next Extension Size"
            entry "Extension Type" [string reverse [ascii 4]] [move -4; format 4]; move 4
            opts "Options"
            if {$extsize != 0} {
            	str $extsize "utf8" "Data"
            }
        }
    }
    goto 0x400
    entry "Data" "" $datsz
} elseif {$magic == "2GMI"} {
    section "IMG2 Superblock Header" {
        entry "Magic" [string reverse [ascii 4]] [move -4; format 4]; move 4
	    set gran [uint32 -hex "Image Granule (block size in bytes)"]
	    set imghdr [uint32 -hex "Image Header Offset"]
	    set bbs [uint32 -hex "Boot Blocksize"]
	    set tg [uint32 -hex "Total granules"]
	    uint32 -hex "NVRAM Granule"
	    uint32 -hex "NVRAM Offset"
	    uint32 -hex "Flags (reserved)"
	    uint32 -hex "Reserved1"
	    uint32 -hex "Reserved2"
	    uint32 -hex "Reserved3"
	    uint32 -hex "Reserved4"
	    uint32 -hex "CRC32 Header Fields"
    }
    set curpos [pos]
    
    set len [expr {$tg * $gran - $bbs * $gran}]
    #if {$len != 0} {
    	entry "Boot" "" [goto [expr {$gran * $bbs}]; format $len]
    
    	if {$imghdr != 0} {
    		entry "Image Header" "" [goto [expr {$gran * ($bbs + $imghdr)}]; format $len]
    	}
    #}
    
} elseif {$magic == "3gmI"} {
    proc parseimg3 {} {
        section "IMG3 Object Header" {
            entry "Magic" [string reverse [ascii 4]] [move -4; format 4]; move 4
            set alen [uint32 -hex "Skip Distance"]
            set blen [uint32 -hex "Buffer Length"]
            set slen [uint32 -hex "Signed Length"]
            entry "Type" [string reverse [ascii 4]] [move -4; format 4]; move 4
            if {$slen > 0} {
            	entry "Signed Buffer" "" [expr {$slen + 0x8}] 0xC
            }
            entry "Buffer" "" $blen
            if {$alen - $blen > 0} {
            	entry "Padding" "" [expr {$alen - $blen}] [expr {[pos] + $blen}]
            }
        
            set tags [dict create\
                DATA "Data"\
                SHSH "Signed Hash"\
                CERT "Certificate Chain"\
                VERS "Version"\
                SEPO "Security Epoch"\
                SDOM "Security Domain"\
                PROD "Production Status"\
                CHIP "Chip Type"\
                BORD "Board Type"\
                ECID "Unique ID"\
                SALT "Random Pad"\
                TYPE "Type"\
                OVRD "Override"\
                CEPO "Hardware Epoch"\
                NONC "Nonce"\
                KBAG "Keybag"\
                RAND "Random"\
            ]
            
            
            set offset {[len] % 4}
            
            while {[pos] < $blen} {
                #puts [concat "reached" [pos]]
                set fourb [string reverse [bytes 4]]
                if {[dict exists $tags $fourb]} { #$fourb in $onlytags
                    #puts "ayo a tag (found ${fourb})"
                    move -4        
                    set dictval [dict get $tags $fourb]
        
                    section "IMG3 Tag" {
                        entry "Tag" "${fourb} (${dictval})" 4; move 4
                        set skipd [uint32 -hex "Skip Distance"]
                        set buf [uint32 -hex "Buffer Length"]
                        set padlen [expr {$skipd - $buf - 12}]
                        if {$fourb in {"DATA" "SHSH" "NONC" "SALT"}} {
                            entry "Buffer" "" $buf
                            move $buf
                        } elseif {$fourb == "VERS"} {
                            section "Buffer" {
                                #typedef struct {
                                #	/* number of valid bytes in the buffer */
                                #	u_int32_t	stringLength;
                                #	char		stringBytes[];
                                #} Image3TagString;
                                set vlen [uint32 -hex "String Length"]
                                str $vlen "utf8" "String Bytes"
                            }
                        } elseif {$fourb == "TYPE"} {
                            set type [string reverse [bytes 4]]; move -4
                            entry "Buffer" $type $buf
                            move $buf
                        } elseif {$fourb == "OVRD"} {
                            uint32 -hex "Buffer"
                        } elseif {$fourb == "KBAG"} {
                            set sel [uint32]; move -4
                            section "Keybag" {
                                entry "Selector" [switch -- $sel {
                                    0 { format "Unencrypted Key" }
                                    1 { format "Production-fused Key"}
                                    2 { format "Development-fused Key"}
                                    default {format "Unknown Selector (%d)" $sel}
                                }] 4; move 4
                                set ksize [expr [uint32] / 8]; move -4
                                entry "Key size" [switch -- $ksize {
                                    16 {format "16 (AES128)"}
                                    24 {format "24 (AES192)"}
                                    32 {format "32 (AES256)"}
                                    default {format "%d (Unknown)" $ksize}
                                }] 4; move 4
                                hex 16 "IV"
                                if {$ksize != 32} {
                                    section "Key" {
                                        hex $ksize "Key"
                                        bytes [expr 32 - $ksize] "Padding" 
                                    }
                                } else {
                                    hex 32 "Key"
                                }
                            }
                        } elseif {$fourb == "CERT"} {
                            #CERT is special in that it may contain a IMG3 inside of it
                            entry "Buffer" "" $buf
                            #below code might be better in exchange of ASN.1 parser?
                            #puts [concat "Cert found, pos" [pos]]
                            #puts [expr {$buf + [pos] - 4}]
                            set curpos [pos]
                            while {[pos] < [expr {$buf + $curpos - 4}]} {
                                #puts [concat "Reached" [pos]]
                                if {[bytes 4] == "3gmI"} {
                                    move -4
                                    parseimg3
                                    break
                                }
                                move -3; #scan each byte
                            }
                            goto $curpos
                            move $buf
                        } elseif {$fourb == "ECID" || $fourb == "RAND"} { #number, but this has a uint64 size
                            uint64 -hex "Buffer"
                        } elseif {$fourb == "SDOM"} {
                            set value [uint32]; move -4
                            #define kImage3SecurityDomainManufacturer	0
                            #define kImage3SecurityDomainDarwin		1
                            #define kImage3SecurityDomainRTXC		3
                            entry "Security Domain" [switch -- $value {
                                        0 { format "%d (Manufacturer)" $value}
                                        1 { format "%d (Darwin)" $value}
                                        3 { format "%d (RTXC)" $value}
                                        default {format "Unknown Security Domain (%d)" $value}
                            }] 4; move 4
                        } else { #assume number
                            uint32 -hex "Buffer"
                            
                            #below are some commented code that might allow us to scan $buf size hexadecimals, 
                            #instead of hardcoding (and assuming) the size of the buffer which may be wrong
                            
                            #binary scan [bytes $buf] c* tmp #with h*, it scans each byte (uint4)
                            #move -4
                            #[expr $tmp & 0xff]
                        }
                        
                        if {$padlen != 0} {
                        	entry "Padding" "" $padlen
                        	move $padlen
                        }
                    }
                }
                #move -3
            }
        }
    }
    parseimg3
}

if {$magic == "8900" || $magic == "8740" || $magic == "8720" || $magic == "8730" || $magic == "8702" || $magic == "8723" || $magic == "8740"} {
   goto [expr {$sigoff + $mov}]
   if {$siglen != 0} {
   	entry "Footer Signature" "" $siglen
   }
   goto [expr {$certoff + $mov}]
   if {$certlen != 0} {
   	entry "Footer Certificate" "" $certlen
   }
}