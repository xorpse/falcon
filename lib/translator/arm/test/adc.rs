use executor::Memory;
use il::*;
use translator::arm::test::get_scalar;
use types::Endian;


#[test]
fn adc_r() {
    // adc r0, r1, r2
    let instruction_bytes = &[0x02, 0x00, 0xa1, 0xe0];

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(10, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "r0"
    );
    assert_eq!(result.value(), 21);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(0xffffffff, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "r0"
    );
    assert_eq!(result.value(), 10);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(0xffffffff, 32)), ("c", const_(0, 1))],
        Memory::new(Endian::Big),
        "r0"
    );
    assert_eq!(result.value(), 9);
}


#[test]
fn adcs_r() {
    // adcs r0, r1, r2
    let instruction_bytes = &[0x02, 0x00, 0xb1, 0xe0];

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(10, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "z"
    );
    assert_eq!(result.value(), 0);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(10, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "v"
    );
    assert_eq!(result.value(), 0);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(0xffffffff, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "v"
    );
    assert_eq!(result.value(), 0);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(10, 32)), ("r2", const_(0x7fffffff, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "v"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn adc_imm() {
    // adc r0, r1, 0x10
    let instruction_bytes = &[0x10, 0x00, 0xa1, 0xe2];

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(0x10, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "r0"
    );
    assert_eq!(result.value(), 0x21);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(0xfffffff0, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "r0"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn adcs_imm() {
    // adc r0, r1, 0x10
    let instruction_bytes = &[0x10, 0x00, 0xb1, 0xe2];

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(0xfffffff0, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "c"
    );
    assert_eq!(result.value(), 1);

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(0xffffff00, 32)), ("c", const_(1, 1))],
        Memory::new(Endian::Big),
        "c"
    );
    assert_eq!(result.value(), 0);
}

