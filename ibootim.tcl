requires 0 "69 42 6F 6F"
little_endian
while {[pos] < [len] - 7} {
    if {[bytes 7] == "iBootIm"} {
        move -7
        section "iBoot Image" {
            ascii 8		"Image Signature"
        	uint32 -hex "Image Adler-32"
        	entry       "Image Type"   [string reverse [ascii 4]] [move -4; format 4]; move 4
        	entry       "Image Format" [string reverse [ascii 4]] [move -4; format 4]; move 4
        	uint16 -hex "Image Width"
        	uint16 -hex "Image Height"
        	int16       "Image H Offset"
        	int16       "Image V Offset"
        	set imglen [uint32 -hex "Image Data Length"]
        	entry       "Reserved"     "" 32; move 32
        	if {$imglen != 0} {
        	    entry       "Image Data"   "" $imglen; move $imglen  
            } else {
                entry       "Image Data"   ""
            }
        }
    }
}