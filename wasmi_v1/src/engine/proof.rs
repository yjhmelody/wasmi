
#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProofKind {
    ValueStack = 0,
}

trait ProofGenerator {
    fn kind() -> ProofKind;

    fn generate_proof(&self) -> Vec<u8>;
}
