little_endian

section "APFS Block Header" {
    uint64 -hex "Checksum"
    uint64 -hex "Block Id"
    uint64 -hex "Version"
    uint16 -hex "Block Type"
    uint16 -hex "Flags"
    uint32 -hex "Padding"
}

interp alias {} tApFS_Uuid        {} bytes 16 
interp alias {} tApFS_Ident       {} uint64
interp alias {} tApFS_Transaction {} uint64
interp alias {} tApFS_Address     {} int64
interp alias {} tApFS_BTreeKey    {} uint64

proc tApFS_BlockRange {label} {
    section $label {
        tApFS_Address "First"
        uint64        "Count"
    }
}

section "Container Superblock" {
    uint32             -hex "Magic Number"
    uint32             -hex "Block Size"
    uint64             -hex "Blocks Count"
    uint64             -hex "Features"
    uint64             -hex "Read Only Features"
    uint64             -hex "Incompatible Features"
    tApFS_Uuid              "Uuid"
    tApFS_Ident        -hex "Next Ident"
    tApFS_Transaction  -hex "Next Transaction"
    uint32             -hex "Descriptor Blocks"
    uint32             -hex "Data Blocks"
    tApFS_Address      -hex "Descriptor Base"
    int32              -hex "Data Base"
    uint32             -hex "Descriptor Next"
    uint32             -hex "Data Next"
    uint32             -hex "Descriptor Index"
    uint32             -hex "Descriptor Length"
    uint32             -hex "Data Index"
    uint32             -hex "Data Length"
    tApFS_Ident        -hex "Space Manager Ident"
    tApFS_Ident        -hex "Objects Map Ident"
    tApFS_Ident        -hex "Reaper Ident"
    bytes 4                 "Reserved For Testing"
    uint32             -hex "Maximum Volumes"
    bytes 800               "Volumes Idents"
    bytes 256               "Counters"
    tApFS_BlockRange        "Blocked Out Of Range"
    tApFS_Ident        -hex "Mapping Tree Ident"
    uint64             -hex "Other Flags"
    tApFS_Address      -hex "Jumpstart EFI"
    tApFS_Uuid              "Fusion Uuid"
    tApFS_BlockRange        "Key Locker"
    bytes 32                "Ephemeral Info"
    bytes 8                 "Reserved For Testing"
}