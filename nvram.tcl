big_endian
section "Apple NVRAM Header" {
    section "CHRP NVRAM Header" {
        uint8 -hex "Signature"
    	uint8 -hex "Checksum"
        #static uint8_t chrp_checksum(const struct chrp_nvram_header *hdr)
        #{
        #	uint16_t sum;
        #	const uint8_t *p;
        #
        #	/* checksum the header (minus the checksum itself) */
        #	sum = hdr->sig;
        #	for (p = (const uint8_t *)&hdr->len; p < hdr->data; p++)
        #		sum += *p;
        #	while (sum > 0xff)
        #		sum = (sum & 0xff) + (sum >> 8);
        #	return sum;
        #}
    	uint16 -hex "Length"
    	ascii 12 "Name"
    }
    uint32 -hex "Adler-32"
    uint32 -hex "Generation"
    entry "Padding" "" 8; move 8
    uint16 -hex "Length"
}