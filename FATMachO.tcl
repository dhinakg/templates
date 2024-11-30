big_endian

include "Utility/General.tcl"

# requires 0 "CAFEBABE"

set SHOULD_DIE 0


proc signature_name {signature} {
    global SHOULD_DIE
    if {$signature == 0xfeedface} { big_endian; return "MH_MAGIC" }
    if {$signature == 0xcefaedfe} { little_endian; return "MH_CIGAM" }
    if {$signature == 0xfeedfacf} { big_endian; return "MH_MAGIC_64" }
    if {$signature == 0xcffaedfe} { little_endian; return "MH_CIGAM_64" }
    if {$signature == 0xcafebabe} { big_endian; return "FAT_MAGIC" }
    if {$signature == 0xbebafeca} { little_endian; return "FAT_CIGAM" }
    if {$signature == 0xcafebabf} { big_endian; return "FAT_MAGIC_64" }
    if {$signature == 0xbfbafeca} { little_endian; return "FAT_CIGAM_64" }
    if {$signature == 0xcbfebabe} { little_endian; return "FAT_GPU" }
    if {$signature == 0xb9faf10e} { little_endian; return "FAT_EFI" }

    if {$SHOULD_DIE} { die "unknown signature ($signature)" }
    return "Unknown: $signature"
}


proc cputype_name {cputype} {
    global SHOULD_DIE
    set CPU_ARCH_ABI64 0x01000000
    set CPU_ARCH_ABI64_32 0x02000000

    if {$cputype == 1} { return "CPU_TYPE_VAX" }
    if {$cputype == 6} { return "CPU_TYPE_MC680x0" }
    if {$cputype == 7} { return "CPU_TYPE_X86" }
    if {$cputype == [expr 7 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_X86_64" }
    if {$cputype == 10} { return "CPU_TYPE_MC98000" }
    if {$cputype == 11} { return "CPU_TYPE_HPPA" }
    if {$cputype == 12} { return "CPU_TYPE_ARM" }
    if {$cputype == [expr 12 | $CPU_ARCH_ABI64] } { return "CPU_TYPE_ARM64" }
    if {$cputype == [expr 12 | $CPU_ARCH_ABI64_32]} { return "CPU_TYPE_ARM64_32" }
    if {$cputype == 13} { return "CPU_TYPE_MC88000" }
    if {$cputype == 14} { return "CPU_TYPE_SPARC" }
    if {$cputype == 15} { return "CPU_TYPE_I860" }
    if {$cputype == 18} { return "CPU_TYPE_POWERPC" }
    if {$cputype == [expr 18 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_POWERPC64" }
    if {$cputype == [expr 19 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_APPLEGPU" }
    if {$cputype == [expr 20 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_AMDGPU" }
    if {$cputype == [expr 21 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_INTELGPU" }
    if {$cputype == [expr 23 | $CPU_ARCH_ABI64]} { return "CPU_TYPE_AIR64" }

    if {$SHOULD_DIE} { die "unknown cputype ($cputype)" }
    return "Unknown: $cputype"
}


proc cpusubtype_name {cputype cpusubtype} {
    global SHOULD_DIE
    set CPU_ARCH_ABI64 0x01000000
    set CPU_ARCH_ABI64_32 0x02000000

    set CPU_SUBTYPE_LIB64 0x80000000
    set CPU_SUBTYPE_PTRAUTH_ABI 0x80000000
    set CPU_SUBTYPE_ARM64_PTR_AUTH_MASK 0x0f000000

    set cpusubtype [expr $cpusubtype & 0x00ffffff]

    # todo
    if {$cputype == 1} { die "CPU_TYPE_VAX" }
    if {$cputype == 6} { die "CPU_TYPE_MC680x0" }
    if {$cputype == 7} { 
        if {$cpusubtype == 3} { return "CPU_SUBTYPE_X86_ALL" }
    }
    if {$cputype == [expr 7 | $CPU_ARCH_ABI64]} { 
        if {$cpusubtype == 3} { return "CPU_SUBTYPE_X86_64_ALL" }
        if {$cpusubtype == 4} { return "CPU_SUBTYPE_X86_ARCH1" }
        if {$cpusubtype == 8} { return "CPU_SUBTYPE_X86_64_H" }
    }
    if {$cputype == 10} { die "CPU_TYPE_MC98000" }
    if {$cputype == 11} { die "CPU_TYPE_HPPA" }
    if {$cputype == 12} { 
        if {$cpusubtype == 0} { return "CPU_SUBTYPE_ARM_ALL" }
        if {$cpusubtype == 5} { return "CPU_SUBTYPE_ARM_V4T" }
        if {$cpusubtype == 6} { return "CPU_SUBTYPE_ARM_V6" }
        if {$cpusubtype == 7} { return "CPU_SUBTYPE_ARM_V5TEJ" }
        if {$cpusubtype == 8} { return "CPU_SUBTYPE_ARM_XSCALE" }
        if {$cpusubtype == 9} { return "CPU_SUBTYPE_ARM_V7" }
        if {$cpusubtype == 10} { return "CPU_SUBTYPE_ARM_V7F" }
        if {$cpusubtype == 11} { return "CPU_SUBTYPE_ARM_V7S" }
        if {$cpusubtype == 12} { return "CPU_SUBTYPE_ARM_V7K" }
        if {$cpusubtype == 13} { return "CPU_SUBTYPE_ARM_V8" }
        if {$cpusubtype == 14} { return "CPU_SUBTYPE_ARM_V6M" }
        if {$cpusubtype == 15} { return "CPU_SUBTYPE_ARM_V7M" }
        if {$cpusubtype == 16} { return "CPU_SUBTYPE_ARM_V7EM" }
        if {$cpusubtype == 17} { return "CPU_SUBTYPE_ARM_V8M" }
    }
    if {$cputype == [expr 12 | $CPU_ARCH_ABI64] } { 
        if {$cpusubtype == 0} { return "CPU_SUBTYPE_ARM64_ALL" }
        if {$cpusubtype == 1} { return "CPU_SUBTYPE_ARM64_V8" }
        if {$cpusubtype == 2} { 
            # if {$cpusubtype & $CPU_SUBTYPE_PTRAUTH_ABI == 0} { return "CPU_SUBTYPE_ARM64E\n(no PAC)" }
            # set auth [expr ($cpusubtype & $CPU_SUBTYPE_ARM64_PTR_AUTH_MASK) >> 24]
            # return "CPU_SUBTYPE_ARM64E (PAC version: $auth)"
            return "CPU_SUBTYPE_ARM64E"
        }
    }
    if {$cputype == [expr 12 | $CPU_ARCH_ABI64_32]} { 
        if {$cpusubtype == 0} { return "CPU_SUBTYPE_ARM64_32_ALL" }
        if {$cpusubtype == 1} { return "CPU_SUBTYPE_ARM64_32_V8" }
     }
    if {$cputype == 13} { die "CPU_TYPE_MC88000" }
    if {$cputype == 14} { die "CPU_TYPE_SPARC" }
    if {$cputype == 15} { die "CPU_TYPE_I860" }
    if {$cputype == 18} { die "CPU_TYPE_POWERPC" }
    if {$cputype == [expr 18 | $CPU_ARCH_ABI64]} { die "CPU_TYPE_POWERPC64" }
    if {$cputype == [expr 19 | $CPU_ARCH_ABI64]} { 
        if {$cpusubtype == 32} { return "CPU_SUBTYPE_APPLEGPU_GX2" }
        if {$cpusubtype == 17} { return "CPU_SUBTYPE_APPLEGPU_G4P" }
        if {$cpusubtype == 49} { return "CPU_SUBTYPE_APPLEGPU_G4G" }
        if {$cpusubtype == 65} { return "CPU_SUBTYPE_APPLEGPU_G5P" }
        if {$cpusubtype == 81} { return "CPU_SUBTYPE_APPLEGPU_G9P" }
        if {$cpusubtype == 97} { return "CPU_SUBTYPE_APPLEGPU_G9G" }
        if {$cpusubtype == 34} { return "CPU_SUBTYPE_APPLEGPU_G10P" }
        if {$cpusubtype == 114} { return "CPU_SUBTYPE_APPLEGPU_G11P" }
        if {$cpusubtype == 82} { return "CPU_SUBTYPE_APPLEGPU_G11M" }
        if {$cpusubtype == 130} { return "CPU_SUBTYPE_APPLEGPU_G11G" }
        if {$cpusubtype == 1602} { return "CPU_SUBTYPE_APPLEGPU_G11G_8FSTP" }
        if {$cpusubtype == 210} { return "CPU_SUBTYPE_APPLEGPU_G12P" }
        if {$cpusubtype == 290} { return "CPU_SUBTYPE_APPLEGPU_G13P" }
        if {$cpusubtype == 322} { return "CPU_SUBTYPE_APPLEGPU_G13G" }
        if {$cpusubtype == 530} { return "CPU_SUBTYPE_APPLEGPU_G13S" }
        if {$cpusubtype == 562} { return "CPU_SUBTYPE_APPLEGPU_G13C" }
        if {$cpusubtype == 594} { return "CPU_SUBTYPE_APPLEGPU_G13D" }
        if {$cpusubtype == 370} { return "CPU_SUBTYPE_APPLEGPU_G14P" }
        if {$cpusubtype == 402} { return "CPU_SUBTYPE_APPLEGPU_G14G" }
        if {$cpusubtype == 434} { return "CPU_SUBTYPE_APPLEGPU_G14S" }
        if {$cpusubtype == 498} { return "CPU_SUBTYPE_APPLEGPU_G14D" }
        if {$cpusubtype == 610} { return "CPU_SUBTYPE_APPLEGPU_G15P" }
    }
    if {$cputype == [expr 20 | $CPU_ARCH_ABI64]} { 
        if {$cpusubtype == 4000} { return "CPU_SUBTYPE_AMD_GFX600" }
        if {$cpusubtype == 4001} { return "CPU_SUBTYPE_AMD_GFX600_NWH" }
        if {$cpusubtype == 4002} { return "CPU_SUBTYPE_AMD_GFX701" }
        if {$cpusubtype == 4003} { return "CPU_SUBTYPE_AMD_GFX704" }
        if {$cpusubtype == 4004} { return "CPU_SUBTYPE_AMD_GFX803" }
        if {$cpusubtype == 4005} { return "CPU_SUBTYPE_AMD_GFX802" }
        if {$cpusubtype == 5000} { return "CPU_SUBTYPE_AMD_GFX900" }
        if {$cpusubtype == 5001} { return "CPU_SUBTYPE_AMD_GFX904" }
        if {$cpusubtype == 5002} { return "CPU_SUBTYPE_AMD_GFX906" }
        if {$cpusubtype == 6000} { return "CPU_SUBTYPE_AMD_GFX1010_NSGC" }
        if {$cpusubtype == 6001} { return "CPU_SUBTYPE_AMD_GFX1010" }
        if {$cpusubtype == 6002} { return "CPU_SUBTYPE_AMD_GFX1011" }
        if {$cpusubtype == 6003} { return "CPU_SUBTYPE_AMD_GFX1012" }
        if {$cpusubtype == 6004} { return "CPU_SUBTYPE_AMD_GFX1030" }
        if {$cpusubtype == 6005} { return "CPU_SUBTYPE_AMD_GFX1032" }
    }
    if {$cputype == [expr 21 | $CPU_ARCH_ABI64]} { 
        if {$cpusubtype == 590342} { return "CPU_SUBTYPE_INTEL_SKL_GT2R6" }
        if {$cpusubtype == 590343} { return "CPU_SUBTYPE_INTEL_SKL_GT2R7" }
        if {$cpusubtype == 590602} { return "CPU_SUBTYPE_INTEL_SKL_GT3R10" }
        if {$cpusubtype == 9765376} { return "CPU_SUBTYPE_INTEL_KBL_GT2R0" }
        if {$cpusubtype == 9765378} { return "CPU_SUBTYPE_INTEL_KBL_GT2R2" }
        if {$cpusubtype == 9765380} { return "CPU_SUBTYPE_INTEL_KBL_GT2R4" }
        if {$cpusubtype == 9765633} { return "CPU_SUBTYPE_INTEL_KBL_GT3R1" }
        if {$cpusubtype == 9765638} { return "CPU_SUBTYPE_INTEL_KBL_GT3R6" }
        if {$cpusubtype == 1115655} { return "CPU_SUBTYPE_INTEL_ICL_1X6X8R7" }
        if {$cpusubtype == 1116167} { return "CPU_SUBTYPE_INTEL_ICL_1X8X8R7" }
    }
    if {$cputype == [expr 23 | $CPU_ARCH_ABI64]} { 
        if {$cpusubtype == 1} { return "CPU_SUBTYPE_AIR_V16" }
        if {$cpusubtype == 2} { return "CPU_SUBTYPE_AIR_V18" }
        if {$cpusubtype == 3} { return "CPU_SUBTYPE_AIR_V111" }
        if {$cpusubtype == 4} { return "CPU_SUBTYPE_AIR_V20" }
        if {$cpusubtype == 5} { return "CPU_SUBTYPE_AIR_V21" }
        if {$cpusubtype == 6} { return "CPU_SUBTYPE_AIR_V22" }
        if {$cpusubtype == 7} { return "CPU_SUBTYPE_AIR_V23" }
        if {$cpusubtype == 8} { return "CPU_SUBTYPE_AIR_V24" }
        if {$cpusubtype == 9} { return "CPU_SUBTYPE_AIR_V25" }
        if {$cpusubtype == 10} { return "CPU_SUBTYPE_AIR_V26" }
    }

    if {$SHOULD_DIE} { die "unknown cpusubtype ($cpusubtype) for cpu type ($cputype)" }
    return "Unknown: $cpusubtype"
}

proc cpusubtype_additional {cputype cpusubtype} {
    set CPU_ARCH_ABI64 0x01000000
    set CPU_ARCH_ABI64_32 0x02000000

    set CPU_SUBTYPE_LIB64 0x80000000
    set CPU_SUBTYPE_PTRAUTH_ABI 0x80000000
    set CPU_SUBTYPE_ARM64_PTR_AUTH_MASK 0x0f000000

    # We should really change this to unconditional, but whatever


    if {$cputype == [expr 12 | $CPU_ARCH_ABI64] } { 
        if {[expr $cpusubtype & 0x00ffffff] == 2} { 
            if {[expr $cpusubtype & $CPU_SUBTYPE_PTRAUTH_ABI] == 0} {
                return [dict create 0 "No ptrauth (iOS 13, disallowed)"]
            }
            set auth [expr ($cpusubtype & $CPU_SUBTYPE_ARM64_PTR_AUTH_MASK) >> 24]
            return [dict create [format %x [expr $CPU_SUBTYPE_PTRAUTH_ABI >> 24]] "PAC version: $auth"]
        }
    }

    return ""
}


section "Header" {
    set magic [uint32 -hex "Magic"]
    # uint32 -hex "Magic"
    entry "Magic" [signature_name $magic] 4 [expr [pos] - 4]
    set count [uint32 "Architecture Count"]

    for {set i 1} {$i <= $count} {incr i} {
        section "Architecture $i" {
            # uint32 -hex "CPU Type"
            set cputype [uint32]
            entry "CPU Type" [cputype_name $cputype] 4 [expr [pos] - 4]
            # uint32 -hex "CPU Subtype"
            set cpusubtype [uint32]
            set additional [cpusubtype_additional $cputype $cpusubtype]
            if {$additional == ""} {
                entry "CPU Subtype" [cpusubtype_name $cputype $cpusubtype] 4 [expr [pos] - 4]
            } else {
                section "CPU Subtype" {
                    # sectionvalue [cpusubtype_name $cputype $cpusubtype]
                    entry "Subtype" [cpusubtype_name $cputype $cpusubtype] 4 [expr [pos] - 4]
                    section "Capabilities" {
                        dict for {key value} $additional {
                            entry $key $value 1 [expr [pos] - 1]
                        }
                    }
                }
            }
            # entry "CPU Subtype" [cpusubtype_name $cputype $cpusubtype] 4 [expr [pos] - 4]
            uint32 -hex "Offset"
            uint32 "Size"
            uint32 "Align"
        }
    }
}