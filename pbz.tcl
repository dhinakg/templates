big_endian

include "Utility/General.tcl"

requires 0 "70627A"
ascii 3 "Magic"
set type [ascii 1]; move -1

entry "Type" [switch -- $type {
	"4" { format "LZ4 (%s)" $type }
	"b" { format "LZBITMAP (%s)" $type }
	"e" { format "LZFSE (%s)" $type }
	"f" { format "LZVN (%s)" $type }
	"x" { format "LZMA (%s)" $type }
    "z" { format "ZLIB (%s)" $type }
    default { format "Unknown" }
}] 1; move 1

set bsize [uint64 -hex "Block Size"]

main_guard {
	section "Blocks" {
    	for {set i 1} {![end]} {incr i} {
    	    section "Block $i" {
    	        set usize [uint64 -hex "Uncompressed Size"]
    	        set size [uint64 -hex "Compressed Size"]
    	        if {$usize == $size} {
    	            sectionname "Block $i (Uncompressed)"
    	            bytes $size "Uncompressed Data"
    	        } else {
    	            bytes $size "Compressed Data"
    	        }
    	    }
    	}
    }
}