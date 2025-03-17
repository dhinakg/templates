big_endian

requires 0 "70627A"
ascii 3
set type [ascii 1]


            # "z": zlib.decompressobj,
            # "x": lzma.LZMADecompressor,
            # # 4: lz4
            # # e: lzfse

switch -- $type {
    "z" { entry "Magic" "ZLIB"  4 0}
    "x" { entry "Magic" "LZMA"  4 0}
    "4" { entry "Magic" "LZ4"  4 0}
    "e" { entry "Magic" "LZFSE" 4 0 }
    default { entry "Magic" "Unknown"  4 0}
}

uint64 "Block Size"

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