big_endian

include "Utility/General.tcl"


requires 0 "70627A"
set type [ascii 4]

switch -- $type {
    "pbzz" { entry "Magic" [format "ZLIB (%s)" $type] 4 0}
    "pbzx" { entry "Magic" [format "LZMA (%s)" $type] 4 0}
    "pbz4" { entry "Magic" [format "LZ4 (%s)" $type] 4 0}
    "pbze" { entry "Magic" [format "LZFSE (%s)" $type] 4 0 }
    default { entry "Magic" "Unknown" 4 0}
}

set bsize [uint64 "Block Size"]

main_guard {
    for {set i 1} {![end]} {incr i} {
        section "Block $i" {
            set usize [uint64 "Uncompressed Size"]
            set size [uint64 "Compressed Size"]
            if {$usize == $size} {
                sectionname "Block $i (Uncompressed)"
                bytes $size "Uncompressed Data"
            } else {
                bytes $size "Compressed Data"
            }
        }
    }
}