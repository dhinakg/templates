big_endian
requires 0 "78617221" ;# xar!
ascii 4 "Signature"
uint16 "Header Size"
uint16 "Version"
set compressed_length [uint64 "TOC Compressed Length"]
uint64 "TOC Uncompressed Length"
uint32 "Checksum"
set compressed_data [bytes $compressed_length "TOC Data"]
set xml [zlib_uncompress $compressed_data]

#puts "${xml}"
package require tdom
set doc [dom parse $xml]
set root [$doc documentElement]
set nodes [$root selectNodes "//file"]
section "Files" {
	foreach node [lreverse $nodes] {
		section [[lindex [$node selectNodes "./name"] 0] text] {
			entry "ID" [$node getAttribute "id"]
			entry "Type" [[lindex [$node selectNodes "./type"] 0] text]
			catch {
				entry "User" [[lindex [$node selectNodes "./user"] 0] text]
			}
			catch {
				entry "Group" [[lindex [$node selectNodes "./group"] 0] text]
			}
			catch {
				entry "UID" [[lindex [$node selectNodes "./uid"] 0] text]
			}
			catch {
				entry "GID" [[lindex [$node selectNodes "./gid"] 0] text]
			}
			catch {
				entry "Mode" [[lindex [$node selectNodes "./mode"] 0] text]
			}
		}
	}
}
