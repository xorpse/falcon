use executor::Memory;
use il::*;
use translator::arm::test::get_scalar;
use types::Endian;


#[test]
fn adr() {
    // add r0, r0, 0
    // addr r0, (pc-12)
    let instruction_bytes = &[0x00, 0x00, 0x80, 0xe2, 0x0c, 0x10, 0x4f, 0xe2];

    let result = get_scalar(
        instruction_bytes,
        vec![("r0", const_(0xdeadbeef, 32))],
        Memory::new(Endian::Big),
        "r1"
    );
    assert_eq!(result.value(), 0);

    // TODO: More tests for adr
}