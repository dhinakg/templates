little_endian
section "Trust Cache" {
	set ver [uint32 "Version"]
	uuid "UUID"
	set entry [uint32 "Number of entries"]
	if {$ver == 0} {
		for {set i 0} {$i < $entry} {incr i} {
			hex 20 "CDHash"
		}
	} elseif {$ver == 1} {
		section "Entries" {
			for {set i 0} {$i < $entry} {incr i} {
				section "Entry" {
					hex 20 "CDHash"
					set ht [uint8]
					entry "Hash type" [switch -- $ht {
						1 {format "CS_HASHTYPE_SHA1"}
						2 {format "CS_HASHTYPE_SHA256"}
						3 {format "CS_HASHTYPE_SHA256_TRUNCATED"}
						4 {format "CS_HASHTYPE_SHA384"}
						default {format "Unknown hash type %d" $ht}
					}] 1 [expr {[pos] - 1}]
					#3 actually 1 | 2
					set flags [uint8]
					entry "Flags" [switch -- $flags {
						0 		{format "None"}
						1 		{format "CS_TRUST_CACHE_AMFID"}
						2 		{format "CS_TRUST_CACHE_ANE"}
						3 		{format "CS_TRUST_CACHE_{AMFID, ANE}"}
						default {format "Unknown flag (%d)" $flags}
					}] 1 [expr {[pos] - 1}]
				}
			}
		}
	} elseif {$ver == 2} {
		section "Entries" {
			for {set i 0} {$i < $entry} {incr i} {
				section "Entry" {
					hex 20 "CDHash"
					set ht [uint8]
					entry "Hash type" [switch -- $ht {
						1 {format "CS_HASHTYPE_SHA1"}
						2 {format "CS_HASHTYPE_SHA256"}
						3 {format "CS_HASHTYPE_SHA256_TRUNCATED"}
						4 {format "CS_HASHTYPE_SHA384"}
						default {format "Unknown hash type %d" $ht}
					}] 1 [expr {[pos] - 1}]
					#3 actually 1 | 2
					set flags [uint8]
					entry "Flags" [switch -- $flags {
						0 		{format "None"}
						1 		{format "CS_TRUST_CACHE_AMFID"}
						2 		{format "CS_TRUST_CACHE_ANE"}
						3 		{format "CS_TRUST_CACHE_{AMFID, ANE}"}
						default {format "Unknown flag (%d)" $flags}
					}] 1 [expr {[pos] - 1}]
					section -collapsed "Constraints" {
						set val [uint8]
						sectionvalue [format "0x%x" $val]
						switch -- $val {
							0 {entry "Constraints" "None" 1 [expr {[pos] - 1}]}
							1 {
							    entry "Self Constraint" "(on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1" 1 [expr {[pos] - 1}]
							    entry "Parent Constraint" "is-init-proc" 1 [expr {[pos] - 1}]
							}
							2 {
							    entry "Self Constraint" "on-authorized-authapfs-volume || on-system-volume" 1 [expr {[pos] - 1}]
							}
							3 {
							    entry "Self Constraint" "(on-authorized-authapfs-volume || on-system-volume) && (launch-type == 0 || launch-type == 1) && validation-category == 1" 1 [expr {[pos] - 1}]
							}
							4 {
							    entry "Self Constraint" "(on-authorized-authapfs-volume || on-system-volume) && (launch-type == 0 || launch-type == 1) && validation-category == 1" 1 [expr {[pos] - 1}]
							    entry "Parent Constraint" "(on-system-volume && signing-identifier == \"com.apple.mbfloagent\" && validation-category == 1) || is-init-proc" 1 [expr {[pos] - 1}]
							}
							5 {
							    entry "Self Constraint" "validation-category == 1" 1 [expr {[pos] - 1}]
							    entry "Parent Constraint" "(on-system-volume && signing-identifier == \"com.apple.mbfloagent\" && validation-category == 1) || is-init-proc" 1 [expr {[pos] - 1}]
							}
							6 {
							    entry "Self Constraint" "(!in-tc-with-constraint-category || is-sip-protected || on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1" 1 [expr {[pos] - 1}]
							    entry "Parent Constraint" "(apple-internal && entitlements\[\"com.apple.private.set-launch-type.internal\"\] == 1) || is-init-proc" 1 [expr {[pos] - 1}]
							}
							7 {
							    entry "Self Constraint" "validation-category == 1" 1 [expr {[pos] - 1}]
							}
							default {entry "Constraints" [format "Unknown constraint %d" $val] 1 [expr {[pos] - 1}]}
						}
					}
					uint8 -hex 
					#"Reserved"
				}
			}
		}
	} else {
		entry "ERROR" {format "Version %d not supported" $ver}
	}
}