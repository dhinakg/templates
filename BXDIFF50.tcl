section "BXDIFF50 header" {
    ascii 8 "Magic"
    uint32 "Input Variants (0 if this is a full replacement)"
    uint32 "Flags (in-place 0x1)"
    uint64 "patched_file_size/uncomp_file_size"
    uint64 "control_size"
    uint64 "source_file_size/extra_size"
    hex 20 "result_sha1"
}