from binaryninja import *


def create_user_func(bv: BinaryView):
    max_addr = 0
    for segment in bv.segments:
        max_addr = max(max_addr, segment.end + 1)
    # Skip one and align to 0x1000
    max_addr += 0x1fff
    max_addr &= ~0xfff

    segment_start = max_addr
    segment_length = 0x1000
    file_start = bv.file.raw.end
    bv.file.raw.insert(file_start, b'\x00' * segment_length)
    bv.add_user_segment(segment_start, segment_length,
                        file_start, segment_length,
                        SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
    bv.add_user_section("rop cave", segment_start, segment_length, SectionSemantics.ReadOnlyCodeSectionSemantics)


    bv.create_user_function(segment_start)
    bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, segment_start, "rop", "rop"))
    func = bv.get_function_at(segment_start)
    func.reanalyze()




