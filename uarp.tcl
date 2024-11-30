big_endian

proc formatType {type} {
    entry "Payload Type" [switch -- $type {
        "FOTA" {return -level 0 "Firmware Over the Air (FOTA)"}
        "P1FW" {return -level 0 "PROTO1 (P1FW)"}
        "P2FW" {return -level 0 "PROTO2 (P2FW)"}
        "EVTF" {return -level 0 "Engineering Validation Test (EVTF)"}
        "PVTF" {return -level 0 "Production Validation Test (PVTF)"}
        "MPFW" {return -level 0 "Mainline Production Firmware (MPFW)"}
        "STFW" {return -level 0 "Storage Firmware (STFW)"}
        "DTTX" {return -level 0 "Data Transmit (DTTX)"}
        "DTRX" {return -level 0 "Data Receive (DTRX)"}
        "DMTP" {return -level 0 "Test Point (DMTP)"}
        "PDFW" {return -level 0 "USB-C Power Delivery (PDFW)"}
        "ULPD" {return -level 0 "Upload (ULPD)"}
        "CHDR" {return -level 0 "Charge Direction (CHDR)"}
        default {format "Unknown type (%s)" $type}
    }] 4; move 4
}

proc formatMetadata {val} {
    entry "Metadata Type" [switch -- $val {
        3436347648 {return -level 0 "Payload Filepath (3,436,347,648)"}
        3436347649 {return -level 0 "Payload Long Name (3,436,347,649)"}
        3436347650 {return -level 0 "Minimum Required Version (3,436,347,650)"}
        3436347651 {return -level 0 "Ignore Version (3,436,347,651)"}
        3436347652 {return -level 0 "Urgent Update (3,436,347,652)"}
        3436347653 {
            return -level 0 "Payload Certificate (3,436,347,653)"
            #Filepath
        }

        3436347654 {
            return -level 0 "Payload Signature (3,436,347,654)"
            #Filepath
        }
        3436347655 {
            return -level 0 "Payload Hash (3,436,347,655)"
            #Filepath
        }
        3436347656 {return -level 0 "Payload Digest (3,436,347,656)"}
        3436347657 {return -level 0 "Minimum Battery Level (3,436,347,657)"}
        3436347658 {return -level 0 "Trigger Battery Level (3,436,347,658)"}
        3436347659 {return -level 0 "Payload Compression ChunkSize (3,436,347,659)"}
        3436347660 {return -level 0 "Payload Compression Algorithm (3,436,347,660)"}
        3436347663 {return -level 0 "Compressed Headers Payload Index (3,436,347,663)"}
        1619725824 {return -level 0 "HeySiri Model Type (1,619,725,824)"}
        1619725825 {return -level 0 "HeySiri Model Locale (1,619,725,825)"}
        1619725826 {return -level 0 "HeySiri Model Hash (1,619,725,826)"}
        1619725827 {return -level 0 "HeySiri Model Role (1,619,725,827)"}
        1619725828 {return -level 0 "HeySiri Model Digest (1,619,725,828)"}
        1619725829 {return -level 0 "HeySiri Model Signature (1,619,725,829)"}
        1619725830 {return -level 0 "HeySiri Model Certificate (1,619,725,830)"}
        1619725831 {return -level 0 "HeySiri Model Engine Version (1,619,725,831)"}
        1619725832 {return -level 0 "HeySiri Model Engine Type (1,619,725,832)"}
        2293403904 {return -level 0 "Personalization Required (2,293,403,904)"}
        2293403905 {return -level 0 "Personalization Payload Tag (2,293,403,905)"}
        2293403906 {return -level 0 "Personalization SuperBinary AssetID (2,293,403,906)"}
        2293403907 {return -level 0 "Personalization Manifest Prefix (2,293,403,907)"}
        3291140096 {return -level 0 "Host Minimum Battery Level (3,291,140,096)"}
        3291140097 {return -level 0 "Host Inactive To Stage Asset (3,291,140,097)"}
        3291140098 {return -level 0 "Host Inactive To Apply Asset (3,291,140,098)"}
        3291140099 {return -level 0 "Host Network Delay (3,291,140,099)"}
        3291140100 {return -level 0 "Host Reconnect After Apply (3,291,140,100)"}
        3291140101 {return -level 0 "Minimum iOS Version (3,291,140,101)"}
        3291140102 {return -level 0 "Minimum macOS Version (3,291,140,102)"}
        3291140103 {return -level 0 "Minimum tvOS Version (3,291,140,103)"}
        3291140104 {return -level 0 "Minimum watchOS Version (3,291,140,104)"}
        3291140105 {return -level 0 "Host Trigger Battery Level (3,291,140,105)"}
        76079616   {return -level 0 "Voice Assist Type (76,079,616)"}
        76079617   {return -level 0 "Voice Assist Locale (76,079,617)"}
        76079618   {return -level 0 "Voice Assist Hash (76,079,618)"}
        76079619   {return -level 0 "Voice Assist Role (76,079,619)"}
        76079620   {return -level 0 "Voice Assist Digest (76,079,620)"}
        76079621   {return -level 0 "Voice Assist Signature (76,079,621)"}
        76079622   {return -level 0 "Voice Assist Certificate (76,079,622)"}
        76079623   {return -level 0 "Voice Assist Engine Version (76,079,623)"}
        default    {format "Unknown Metadata Type (%d)" $val}
    }] 4; move 4
}

proc parseMetadata {mo ml} {
    set curpos [pos]
    goto $mo
    section "Metadatas" {
        for {set i 0} {$i < $ml} {} {
            section "Metadata" {
                set mt [uint32]; move -4
                formatMetadata $mt
                set mvl [uint32 -hex "Metadata Length"]
                switch -- $mvl {
                    2 {uint16 -hex "Value"}
                    4 {uint32 -hex "Value"}
                    default {hex $mvl "Value"}
                }
            }
            incr i [expr {8 + $mvl}]
        }
    }
    goto $curpos
}

section "UARP Header" {
    # BE, == 2
    uint32 -hex "Version"
    # Version 2 header size == 0x2C
    uint32 -hex "Size"
    # Length of the binary. Metadata plist follows immediately after.
    uint32 -hex "Binary Size"
    section -collapsed "Version" {
        # 100 in '100.7916.1052884864.1'.
        set ma [uint32 "Major Version"]
        # 7916 in '100.7916.1052884864.1'.
        set mi [uint32 "Minor Version"]
        # 1052884864 in '100.7916.1052884864.1'.
        set r [uint32 "Release Version"]
        # 1 in '100.7916.1052884864.1'.
        set b [uint32 "Build Version"]
        sectionvalue [format "%u.%u.%u.%u" $ma $mi $r $b]
    }
    # Typically present after the full header.
    set mo [uint32 -hex "Metadata Offset"]
    # Note that metadata can be 0 in length.
    set ml [uint32 -hex "Metadata Length"]
    # Immediately follows UARP header.
    set ro [uint32 -hex "Row Offset"]
    # Divide by row size (0x28) to determine. 0xC8 defines five.
    set rl [uint32 -hex "Row Length"]

    if {$ml != 0} {
        parseMetadata $mo $ml
    }
}
goto $ro

set rows [expr {$rl / [uint32]}]; move -4
for {set i 0} {$i < $rows} {incr i} {
    section "UARP Row" {
        uint32 -hex "Row Size"
        # For example 'FOTA'
        set pt [ascii 4]; move -4
        formatType $pt
        # All versions within rows appear to match the binary header.
        section -collapsed "Version" {
            set ma [uint32 "Major Version"]
            set mi [uint32 "Minor Version"]
            set r [uint32 "Release Version"]
            set b [uint32 "Build Version"]
            sectionvalue [format "%u.%u.%u.%u" $ma $mi $r $b]
        }
        # Both offset/length typically match the UARP header.
        set mo [uint32 -hex "Metadata Offset"]
        set ml [uint32 -hex "Metadata Length"]
        # Offset within file.
        set po [uint32 -hex "Payload Offset"]
        # Should never exceed binary size.
        set pl [uint32 -hex "Payload Length"]

        if {$ml != 0} {
            parseMetadata $mo $ml
        }

        if {$pl != 0} {
            set curpos [pos]
            goto $po
            bytes $pl "Payload"
            goto $curpos
        }
    }
}

goto [expr {$po + $pl}]

if {[pos] != [end]} {
    bytes eof "SuperBinary"
}