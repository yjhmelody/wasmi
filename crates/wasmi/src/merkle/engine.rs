use crate::{
    engine::bytecode::Instruction,
    snapshot::{
        CallStackSnapshot,
        EngineConfig,
        EngineSnapshot,
        FuncFrameSnapshot,
        ValueStackSnapshot,
    },
    GlobalEntity,
};
use codec::{Encode, Output};

use crate::engine::code_map::CodeMap;
use accel_merkle::{digest::Digest, sha3::Keccak256, Bytes32, Merkle, MerkleType};

impl EngineSnapshot {
    pub fn hash(&self) -> Bytes32 {
        todo!()
    }
}

impl ValueStackSnapshot {
    pub fn hash(&self) -> Bytes32 {
        todo!()
    }
}

// Note: For static state(such as instructions), we just need to generate merkle once and keep it in memory.

impl CodeMap {
    pub fn merkle(&self) -> Merkle {
        Merkle::new(
            MerkleType::Instruction,
            self.insts.iter().map(|i| i.hash()).collect(),
        )
    }
}

impl Encode for Instruction {
    fn size_hint(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.repr().to_le_bytes());

        match self {
            Instruction::MemorySize |
            Instruction::MemoryGrow |
            // const op is not defined here.
            // arith
            Instruction::I32Eqz |
            Instruction::I32Eq |
            Instruction::I32Ne |
            Instruction::I32LtS |
            Instruction::I32LtU |
            Instruction::I32GtS |
            Instruction::I32GtU |
            Instruction::I32LeS |
            Instruction::I32LeU |
            Instruction::I32GeS |
            Instruction::I32GeU |

            Instruction::I64Eqz |
            Instruction::I64Eq |
            Instruction::I64Ne |
            Instruction::I64LtS |
            Instruction::I64LtU |
            Instruction::I64GtS |
            Instruction::I64GtU |
            Instruction::I64LeS |
            Instruction::I64LeU |
            Instruction::I64GeS |
            Instruction::I64GeU |

            Instruction::F32Eq |
            Instruction::F32Ne |
            Instruction::F32Lt |
            Instruction::F32Gt |
            Instruction::F32Le |
            Instruction::F32Ge |

            Instruction::F64Eq |
            Instruction::F64Ne |
            Instruction::F64Lt |
            Instruction::F64Gt |
            Instruction::F64Le |
            Instruction::F64Ge |

            Instruction::I32Clz |
            Instruction::I32Ctz |
            Instruction::I32Popcnt |
            Instruction::I32Add |
            Instruction::I32Sub |
            Instruction::I32Mul |
            Instruction::I32DivS |
            Instruction::I32DivU |
            Instruction::I32RemS |
            Instruction::I32RemU |
            Instruction::I32And |
            Instruction::I32Or |
            Instruction::I32Xor |
            Instruction::I32Shl |
            Instruction::I32ShrS |
            Instruction::I32ShrU |
            Instruction::I32Rotl |
            Instruction::I32Rotr |

            Instruction::I64Clz |
            Instruction::I64Ctz |
            Instruction::I64Popcnt |
            Instruction::I64Add |
            Instruction::I64Sub |
            Instruction::I64Mul |
            Instruction::I64DivS |
            Instruction::I64DivU |
            Instruction::I64RemS |
            Instruction::I64RemU |
            Instruction::I64And |
            Instruction::I64Or |
            Instruction::I64Xor |
            Instruction::I64Shl |
            Instruction::I64ShrS |
            Instruction::I64ShrU |
            Instruction::I64Rotl |
            Instruction::I64Rotr |

            Instruction::F32Abs |
            Instruction::F32Neg |
            Instruction::F32Ceil |
            Instruction::F32Floor |
            Instruction::F32Trunc |
            Instruction::F32Nearest |
            Instruction::F32Sqrt |
            Instruction::F32Add |
            Instruction::F32Sub |
            Instruction::F32Mul |
            Instruction::F32Div |
            Instruction::F32Min |
            Instruction::F32Max |
            Instruction::F32Copysign |

            Instruction::F64Abs |
            Instruction::F64Neg |
            Instruction::F64Ceil|
            Instruction::F64Floor |
            Instruction::F64Trunc |
            Instruction::F64Nearest |
            Instruction::F64Sqrt |
            Instruction::F64Add |
            Instruction::F64Sub |
            Instruction::F64Mul |
            Instruction::F64Div  |
            Instruction::F64Min |
            Instruction::F64Max |
            Instruction::F64Copysign |

            Instruction::I32WrapI64 |
            Instruction::I32TruncSF32 |
            Instruction::I32TruncUF32 |
            Instruction::I32TruncSF64 |
            Instruction::I32TruncUF64 |
            Instruction::I64ExtendSI32 |
            Instruction::I64ExtendUI32 |
            Instruction::I64TruncSF32 |
            Instruction::I64TruncUF32 |
            Instruction::I64TruncSF64 |
            Instruction::I64TruncUF64 |
            Instruction::F32ConvertSI32 |
            Instruction::F32ConvertUI32 |
            Instruction::F32ConvertSI64 |
            Instruction::F32ConvertUI64 |
            Instruction::F32DemoteF64 |
            Instruction::F64ConvertSI32 |
            Instruction::F64ConvertUI32 |
            Instruction::F64ConvertSI64 |
            Instruction::F64ConvertUI64 |
            Instruction::F64PromoteF32 |
            Instruction::I32ReinterpretF32 |
            Instruction::I64ReinterpretF64 |
            Instruction::F32ReinterpretI32 |
            Instruction::F64ReinterpretI64 |

            Instruction::I32Extend8S |
            Instruction::I32Extend16S |
            Instruction::I64Extend8S |
            Instruction::I64Extend16S |
            Instruction::I64Extend32S  => {
                // nop
            },

            Instruction::LocalGet { local_depth } |
            Instruction::LocalSet { local_depth } |
            Instruction::LocalTee { local_depth }  => {
                (local_depth.into_inner() as u32).encode_to(dest);
            },

            Instruction::Br (param) |
            Instruction::BrIfEqz (param) |
            Instruction::BrIfNez (param)  => {
                param.encode_to(dest);
            },

            Instruction::Return (drop_keep) |
            Instruction::ReturnIfNez (drop_keep)  => {
                drop_keep.encode().encode_to(dest);
            }

            Instruction::BrTable {len_targets}  => {
                (*len_targets as u32).encode_to(dest);
            }

            Instruction::Call(idx) => {
                idx.into_inner().encode_to(dest)
            }

            Instruction::CallIndirect(idx) => {
                idx.into_inner().encode_to(dest)
            }

            Instruction::GlobalGet(idx) |
            Instruction::GlobalSet(idx)
            => {
                idx.into_inner().encode_to(dest)
            },

            Instruction::I32Load(offset) |
            Instruction::I64Load(offset) |
            Instruction::F32Load(offset) |
            Instruction::F64Load(offset) |
            Instruction::I32Load8S(offset) |
            Instruction::I32Load8U(offset) |
            Instruction::I32Load16S(offset) |
            Instruction::I32Load16U(offset) |
            Instruction::I64Load8S(offset) |
            Instruction::I64Load8U(offset) |
            Instruction::I64Load16S(offset) |
            Instruction::I64Load16U(offset) |
            Instruction::I64Load32S(offset) |
            Instruction::I64Load32U(offset) |
            Instruction::I32Store(offset) |
            Instruction::I64Store(offset) |
            Instruction::F32Store(offset) |
            Instruction::F64Store(offset) |
            Instruction::I32Store8(offset) |
            Instruction::I32Store16(offset) |
            Instruction::I64Store8(offset) |
            Instruction::I64Store16(offset) |
            Instruction::I64Store32(offset)
            => {
                offset.into_inner().encode_to(dest)
            },

            Instruction::Const(val)
            => {
                val.encode_to(dest)
            },
            _ => {}
        }
    }
}

impl Instruction {
    pub fn hash(&self) -> Bytes32 {
        let mut h = Keccak256::new();
        // Variable length encoding according to the concrete instruction.
        h.update(self.encode());

        h.finalize().into()
    }

    #[allow(unused)]
    fn repr(&self) -> u16 {
        match self {
            Instruction::Unreachable => 0x00,
            Instruction::Br(..) => 0x0C,
            Instruction::BrTable { .. } => 0x0E,
            Instruction::Return { .. } => 0x0F,
            Instruction::Call { .. } => 0x10,
            Instruction::CallIndirect { .. } => 0x11,
            Instruction::Drop => 0x1A,
            Instruction::Select => 0x1B,

            Instruction::LocalGet { .. } => 0x20,
            Instruction::LocalSet { .. } => 0x21,
            Instruction::LocalTee { .. } => 0x22,
            Instruction::GlobalGet { .. } => 0x23,
            Instruction::GlobalSet { .. } => 0x24,

            // load
            Instruction::I32Load(..) => 0x28,
            Instruction::I64Load(..) => 0x29,
            Instruction::F32Load(..) => 0x2A,
            Instruction::F64Load(..) => 0x2B,
            Instruction::I32Load8S(..) => 0x2C,
            Instruction::I32Load8U(..) => 0x2D,
            Instruction::I32Load16S(..) => 0x2E,
            Instruction::I32Load16U(..) => 0x2F,
            Instruction::I64Load8S(..) => 0x30,
            Instruction::I64Load8U(..) => 0x31,
            Instruction::I64Load16S(..) => 0x32,
            Instruction::I64Load16U(..) => 0x33,
            Instruction::I64Load32S(..) => 0x34,
            Instruction::I64Load32U(..) => 0x35,
            // store
            Instruction::I32Store(..) => 0x36,
            Instruction::I64Store(..) => 0x37,
            Instruction::F32Store(..) => 0x38,
            Instruction::F64Store(..) => 0x39,
            Instruction::I32Store8(..) => 0x3A,
            Instruction::I32Store16(..) => 0x3B,
            Instruction::I64Store8(..) => 0x3C,
            Instruction::I64Store16(..) => 0x3D,
            Instruction::I64Store32(..) => 0x3E,
            // memory
            Instruction::MemorySize => 0x3F,
            Instruction::MemoryGrow => 0x40,
            // const op is not defined here.
            // arith
            Instruction::I32Eqz => 0x45,
            Instruction::I32Eq => 0x46,
            Instruction::I32Ne => 0x47,
            Instruction::I32LtS => 0x48,
            Instruction::I32LtU => 0x49,
            Instruction::I32GtS => 0x4A,
            Instruction::I32GtU => 0x4B,
            Instruction::I32LeS => 0x4C,
            Instruction::I32LeU => 0x4D,
            Instruction::I32GeS => 0x4E,
            Instruction::I32GeU => 0x4F,

            Instruction::I64Eqz => 0x50,
            Instruction::I64Eq => 0x51,
            Instruction::I64Ne => 0x52,
            Instruction::I64LtS => 0x53,
            Instruction::I64LtU => 0x54,
            Instruction::I64GtS => 0x55,
            Instruction::I64GtU => 0x56,
            Instruction::I64LeS => 0x57,
            Instruction::I64LeU => 0x58,
            Instruction::I64GeS => 0x59,
            Instruction::I64GeU => 0x5A,

            Instruction::F32Eq => 0x5B,
            Instruction::F32Ne => 0x5C,
            Instruction::F32Lt => 0x5D,
            Instruction::F32Gt => 0x5E,
            Instruction::F32Le => 0x5F,
            Instruction::F32Ge => 0x60,

            Instruction::F64Eq => 0x61,
            Instruction::F64Ne => 0x62,
            Instruction::F64Lt => 0x63,
            Instruction::F64Gt => 0x64,
            Instruction::F64Le => 0x65,
            Instruction::F64Ge => 0x66,

            Instruction::I32Clz => 0x67,
            Instruction::I32Ctz => 0x68,
            Instruction::I32Popcnt => 0x69,
            Instruction::I32Add => 0x6A,
            Instruction::I32Sub => 0x6B,
            Instruction::I32Mul => 0x6C,
            Instruction::I32DivS => 0x6D,
            Instruction::I32DivU => 0x6E,
            Instruction::I32RemS => 0x6F,
            Instruction::I32RemU => 0x70,
            Instruction::I32And => 0x71,
            Instruction::I32Or => 0x72,
            Instruction::I32Xor => 0x73,
            Instruction::I32Shl => 0x74,
            Instruction::I32ShrS => 0x75,
            Instruction::I32ShrU => 0x76,
            Instruction::I32Rotl => 0x77,
            Instruction::I32Rotr => 0x78,

            Instruction::I64Clz => 0x79,
            Instruction::I64Ctz => 0x7A,
            Instruction::I64Popcnt => 0x7B,
            Instruction::I64Add => 0x7C,
            Instruction::I64Sub => 0x7D,
            Instruction::I64Mul => 0x7E,
            Instruction::I64DivS => 0x7F,
            Instruction::I64DivU => 0x80,
            Instruction::I64RemS => 0x81,
            Instruction::I64RemU => 0x82,
            Instruction::I64And => 0x83,
            Instruction::I64Or => 0x84,
            Instruction::I64Xor => 0x85,
            Instruction::I64Shl => 0x86,
            Instruction::I64ShrS => 0x87,
            Instruction::I64ShrU => 0x88,
            Instruction::I64Rotl => 0x89,
            Instruction::I64Rotr => 0x8A,

            Instruction::F32Abs => 0x8B,
            Instruction::F32Neg => 0x8C,
            Instruction::F32Ceil => 0x8D,
            Instruction::F32Floor => 0x8E,
            Instruction::F32Trunc => 0x8F,
            Instruction::F32Nearest => 0x90,
            Instruction::F32Sqrt => 0x91,
            Instruction::F32Add => 0x92,
            Instruction::F32Sub => 0x93,
            Instruction::F32Mul => 0x94,
            Instruction::F32Div => 0x95,
            Instruction::F32Min => 0x96,
            Instruction::F32Max => 0x97,
            Instruction::F32Copysign => 0x98,

            Instruction::F64Abs => 0x99,
            Instruction::F64Neg => 0x9A,
            Instruction::F64Ceil => 0x9B,
            Instruction::F64Floor => 0x9C,
            Instruction::F64Trunc => 0x9D,
            Instruction::F64Nearest => 0x9E,
            Instruction::F64Sqrt => 0x9F,
            Instruction::F64Add => 0xA0,
            Instruction::F64Sub => 0xA1,
            Instruction::F64Mul => 0xA2,
            Instruction::F64Div => 0xA3,
            Instruction::F64Min => 0xA4,
            Instruction::F64Max => 0xA5,
            Instruction::F64Copysign => 0xA6,

            Instruction::I32WrapI64 => 0xA7,
            Instruction::I32TruncSF32 => 0xA8,
            Instruction::I32TruncUF32 => 0xA9,
            Instruction::I32TruncSF64 => 0xAA,
            Instruction::I32TruncUF64 => 0xAB,
            Instruction::I64ExtendSI32 => 0xAC,
            Instruction::I64ExtendUI32 => 0xAD,
            Instruction::I64TruncSF32 => 0xAE,
            Instruction::I64TruncUF32 => 0xAF,
            Instruction::I64TruncSF64 => 0xB0,
            Instruction::I64TruncUF64 => 0xB1,
            Instruction::F32ConvertSI32 => 0xB2,
            Instruction::F32ConvertUI32 => 0xB3,
            Instruction::F32ConvertSI64 => 0xB4,
            Instruction::F32ConvertUI64 => 0xB5,
            Instruction::F32DemoteF64 => 0xB6,
            Instruction::F64ConvertSI32 => 0xB7,
            Instruction::F64ConvertUI32 => 0xB8,
            Instruction::F64ConvertSI64 => 0xB9,
            Instruction::F64ConvertUI64 => 0xBA,
            Instruction::F64PromoteF32 => 0xBB,
            Instruction::I32ReinterpretF32 => 0xBC,
            Instruction::I64ReinterpretF64 => 0xBD,
            Instruction::F32ReinterpretI32 => 0xBE,
            Instruction::F64ReinterpretI64 => 0xBF,

            Instruction::I32Extend8S => 0xC0,
            Instruction::I32Extend16S => 0xC1,
            Instruction::I64Extend8S => 0xC2,
            Instruction::I64Extend16S => 0xC3,
            Instruction::I64Extend32S => 0xC4,

            // Internal instruction that is not in wasm spec.
            // TODO: make sure these instructions.
            Instruction::I32TruncSatF32S => 0x8005,
            Instruction::I32TruncSatF32U => 0x8006,
            Instruction::I32TruncSatF64S => 0x8007,
            Instruction::I32TruncSatF64U => 0x8008,
            Instruction::I64TruncSatF32S => 0x8009,
            Instruction::I64TruncSatF32U => 0x800A,
            Instruction::I64TruncSatF64S => 0x800B,
            Instruction::I64TruncSatF64U => 0x800C,

            Instruction::BrIfEqz(..) => 0x8001,
            Instruction::BrIfNez(..) => 0x8002,
            Instruction::ReturnIfNez(..) => 0x8003,
            Instruction::Const(..) => 0x8004,
        }
    }
}
