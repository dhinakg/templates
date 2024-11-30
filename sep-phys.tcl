little_endian

proc K {a b} {return $a}

proc lequal {l1 l2} {
    if {[llength $l1] != [llength $l2]} {
        return false
    }

    set l2 [lsort $l2]

    foreach elem $l1 {
        set idx [lsearch -exact -sorted $l2 $elem]
        if {$idx == -1} {
            return false
        } else {
            set l2 [lreplace [K $l2 [unset l2]] $idx $idx]
        }
    }

    return [expr {[llength $l2] == 0}]
}

proc permFormat {perms} {
	# L4_Readable
	set VMPERM_RD        [expr {1 << 2}]
	# L4_Writable
	set VMPERM_WR        [expr {1 << 1}]
	# L4_eXecutable
	set VMPERM_EX        [expr {1 << 0}]
	# L4_NoAccess
	set VMPERM_NONE      0      
	
	set VMPERM_SHARE     [expr {1 << 4}]
	# downgrade permissions after proc init, inherit from segment SG_READ_ONLY
	set VMPERM_DOWNGRADE [expr {1 << 5}]
	# log activities with this set
	set VMPERM_TRACE     [expr {1 << 6}]
	
	set VMPERM_RW        [expr {$VMPERM_RD | $VMPERM_WR}]
	set VMPERM_MMU       [expr {$VMPERM_RW | $VMPERM_EX}]
	set VMPERM_STICKY    [expr {$VMPERM_DOWNGRADE | $VMPERM_TRACE}]
	set VMPERM_ALL       [expr {$VMPERM_RD | $VMPERM_WR | $VMPERM_EX | $VMPERM_SHARE | $VMPERM_DOWNGRADE | $VMPERM_TRACE}]

	#first check these so we don't waste time
	if {$perms == $VMPERM_NONE}                  {
		return "VMPERM_NONE (0x0)"
	} elseif {($perms & 0xFF) == $VMPERM_RW}     {
		return "VMPERM_RW (0x6)"
	} elseif {($perms & 0xFF) == $VMPERM_MMU}    {
		return "VMPERM_MMU (0x3)"
	} elseif {($perms & 0xFF) == $VMPERM_STICKY} {
		return "VMPERM_STICKY (0x60)"
	} elseif {($perms & 0xFF) == $VMPERM_ALL}    {
		return "VMPERM_ALL (0x77)"
	}

	#only do these if the others failed
	set curperms {}
	if {($perms & $VMPERM_RD)        == $VMPERM_RD} 	   {lappend curperms "VMPERM_RD"}
	if {($perms & $VMPERM_WR)        == $VMPERM_WR} 	   {lappend curperms "VMPERM_WR"}
	if {($perms & $VMPERM_EX)        == $VMPERM_EX} 	   {lappend curperms "VMPERM_EX"}
	if {($perms & $VMPERM_SHARE)     == $VMPERM_SHARE} 	   {lappend curperms "VMPERM_SHARE"}
	if {($perms & $VMPERM_DOWNGRADE) == $VMPERM_DOWNGRADE} {lappend curperms "VMPERM_DOWNGRADE"}
	if {($perms & $VMPERM_TRACE)     == $VMPERM_TRACE} 	   {lappend curperms "VMPERM_TRACE"}

	set fr [join $curperms " | "]
	set nfr [format " (0x%x)" $perms]
	return $fr$nfr
}

while {1} {
	set test [uint8]; move -1
	#          > 'z'          < 'A'          != <space>
	if {($test > 122 || $test < 65) && $test != 32} {break}
	section "Physical Range" {
		entry "Context" [string reverse [ascii 4]] [move -4; return -level 0 4]; move 4
		entry "Name" [string reverse [ascii 4]] [move -4; return -level 0 4]; move 4
		uint64 -hex "Start"
		uint32 -hex "Size"
		entry "Perms" [permFormat [uint32]] [move -4; return -level 0 4]; move 4
	}
}