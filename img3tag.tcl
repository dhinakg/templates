little_endian
section "IMG3 Tag" {
   #puts [concat "reached" [pos]]
   set fourb [string reverse [bytes 4]]; move -4
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
   ]
       
    set dictval [dict get $tags $fourb]
       
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
        #If you find a IMG3 file containing this tag,
        #pls contact @plzdonthaxme so that I can implement this!
        #entry "Buffer" "bitmap" $buf
        #move $buf
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
        entry "Buffer" "" $buf
    } elseif {$fourb == "ECID"} { #number, but this has a uint64 size
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