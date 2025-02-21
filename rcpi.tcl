little_endian

section "RCPI" {
	section "RCPI Info" {
		uint32 -hex "Type"
		ascii 10 "Version"
		ascii 40 "File Name"
	}
	section "Configs" {
		uint32 -hex "Type"
		set c [uint32 -hex "Config Count"]
		for {set i 0} {$i < $c} {incr i} {
			section "Config" {
				uint64 -hex "Unknown"
				set l [uint32 -hex "Length"]
				section "Files" {
					for {set j 0} {$j < $l} {incr j 4} {
						ascii 4 "File"
					}
				}
			}
		}
	}
	section "Digests" {
		uint32 -hex "Type"
		set c [uint32 -hex "Files Count"]
		for {set i 0} {$i < $c} {incr i} {
			section "File" {
				ascii 4 "Name"
				hex 48 "SHA-384"
			}
		}
	}
	section "Unknown" {
		uint32 -hex "Type"
		set sc [uint32 -hex "Sections Count"]
		for {set i 0} {$i < $sc} {incr i} {
			section "Unknown" {
				uint32 -hex "Unknown"
				set c [uint32 -hex "Values Count"]
				for {set j 0} {$j < $c} {incr j} {
					section "RCPI Value" {
						uint32 -hex "Unknown"
						ascii 4 "Type"
					}
				}
			}
		}
	}
	section "Verifiers" {
		uint32 -hex "Type"
		set c [uint32 -hex "File Count"]
		for {set i 0} {$i < $c} {incr i} {
			section "File" {
				ascii 4 "Name"
				ascii 4 "Verifier"
			}
		}
	}
}
