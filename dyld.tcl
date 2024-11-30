section "dyld_cache_header" {
    ascii 16 "magic"
	uint32 -hex "mappingOffset"
	uint32 -hex "mappingCount"
	uint32 -hex "imagesOffset"
	uint32 -hex "imagesCount"
	uint64 -hex "dyldBaseAddress"
	uint64 -hex "codeSignatureOffset"
	uint64 -hex "codeSignatureSize"
	uint64 -hex "slideInfoOffset"
	uint64 -hex "slideInfoSize"
}