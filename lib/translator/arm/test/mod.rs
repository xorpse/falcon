use executor::*;
use memory;
use il::*;
use RC;
use translator::arm::*;
use types::{Architecture, Endian};


mod adc;
mod add;
mod adr;

#[macro_use]
macro_rules! backing {
    ($e: expr) => {
        {
            let v: Vec<u8> = $e.to_vec();
            let mut b = memory::backing::Memory::new(Endian::Big);
            b.set_memory(0, v, memory::MemoryPermissions::EXECUTE);
            b
        }
    }
}


fn init_driver_block<'d>(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory_: Memory<'d>
) -> Driver<'d> {
    let mut bytes = instruction_bytes.to_vec();
    // and r0, r0, r0
    bytes.append(&mut vec![0x00, 0x00, 0x00, 0xe0]);

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(0, bytes,
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ);
    
    let function = Arm::new().translate_function(&backing, 0).unwrap();

    println!("{}", function.control_flow_graph());

    let location = if function.control_flow_graph()
                              .block(0).unwrap()
                              .instructions().len() == 0 {
        ProgramLocation::new(Some(0), FunctionLocation::EmptyBlock(0))
    }
    else {
        ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0))
    };

    let mut program = Program::new();
    program.add_function(function);

    let mut state = State::new(memory_);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(RC::new(program), location, state, Architecture::Arm)
}


fn init_driver_function<'d>(
    backing: &'d memory::backing::Memory,
    scalars: Vec<(&str, Constant)>
) -> Driver<'d> {

    let memory = Memory::new_with_backing(Endian::Big, backing);

    let function = Arm::new().translate_function(&memory, 0).unwrap();
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0));

    let mut state = State::new(memory);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(RC::new(program), location, state, Architecture::Arm)
}


fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
    result_scalar: &str
) -> Constant {

    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

    while driver.location()
                .apply(driver.program()).unwrap()
                .forward().unwrap()
                .len() > 0 {
        driver = driver.step().unwrap();
    }

    driver.state()
        .get_scalar(result_scalar)
        .expect(&format!("Could not get scalar {}", result_scalar))
        .clone()
}


fn get_raise(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory
) -> Expression {

    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

    loop {
        {
            let location = driver.location().apply(driver.program()).unwrap();
            if let Some(instruction) = location.instruction() {
                if let Operation::Raise { ref expr } = *instruction.operation() {
                    return expr.clone();
                }
            }
        }
        driver = driver.step().unwrap();
    }
}


fn step_to(mut driver: Driver, target_address: u64) -> Driver {

    loop {
        driver = driver.step().unwrap();
        if let Some(address) = driver.location()
                                     .apply(driver.program())
                                     .unwrap()
                                     .address() {
            if address == target_address {
                return driver;
            }
        }
    }
}