use crate::{
    engine::{InstProofParams, ProofError},
    proof::{CodeMerkle, InstanceMerkle, InstructionProof, OspProof, VersionedOspProof},
    AsContext,
    Engine,
    Instance,
    InstanceEntity,
    Store,
    StoreContext,
};
use accel_merkle::MerkleHasher;
use core::marker::PhantomData;

/// A builder for creating code proof by store.
#[derive(Debug)]
pub struct CodeProofBuilder<'a, T, Hasher: MerkleHasher> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance_entity: &'a InstanceEntity,
    pub(crate) _hasher: PhantomData<Hasher>,
}

impl<'a, T, Hasher: MerkleHasher> AsContext for CodeProofBuilder<'a, T, Hasher> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Hasher: MerkleHasher> CodeProofBuilder<'a, T, Hasher> {
    /// Make a static merkle from the inner directly.
    ///
    /// # Note
    ///
    /// It is used to avoid duplicated computing.
    pub fn make_code_merkle(&self) -> CodeMerkle<Hasher> {
        CodeMerkle::<Hasher>::generate(
            self.as_context(),
            self.instance_entity.funcs(),
            self.store.engine().clone(),
        )
    }
}

/// A builder for creating osp proof by store.
#[derive(Debug)]
pub struct OspProofBuilder<'a, T, Hasher: MerkleHasher> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance: Instance,
    pub(crate) instance_entity: &'a InstanceEntity,
    pub(crate) code_merkle: &'a CodeMerkle<Hasher>,
}

impl<'a, T, Hasher: MerkleHasher> AsContext for OspProofBuilder<'a, T, Hasher> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Hasher: MerkleHasher> OspProofBuilder<'a, T, Hasher> {
    /// Creates the latest version osp proof data.
    pub fn make_osp_proof(&self, current_pc: u32) -> Result<VersionedOspProof<Hasher>, ProofError> {
        self.make_osp_proof_v0(current_pc)
            .map(VersionedOspProof::V0)
    }
    /// Creates an ops proof according to current pc.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn make_osp_proof_v0(&self, current_pc: u32) -> Result<OspProof<Hasher>, ProofError> {
        let instance_merkle = self.make_instance_merkle();
        let inst_proof = self.make_inst_proof(&instance_merkle, current_pc)?;
        let engine_proof = self.engine().make_engine_proof::<Hasher>(inst_proof.inst)?;

        let globals_root = instance_merkle
            .globals
            .as_ref()
            .map(|globals| globals.root());
        let table_roots = instance_merkle
            .tables
            .iter()
            .map(|table| table.merkle.root())
            .collect();
        let memory_roots = instance_merkle
            .memories
            .iter()
            .map(|mem| mem.merkle.root())
            .collect();

        Ok(OspProof::<Hasher> {
            globals_root,
            table_roots,
            memory_roots,
            engine_proof,
            inst_proof,
        })
    }

    /// Creates instance merkle for current wasm state.
    fn make_instance_merkle(&self) -> InstanceMerkle<Hasher> {
        let instance_snapshot = self
            .instance_entity
            .make_snapshot(self.as_context(), self.engine().clone());
        InstanceMerkle::generate(instance_snapshot)
    }

    pub fn make_inst_proof(
        &self,
        instance_merkle: &InstanceMerkle<Hasher>,
        current_pc: u32,
    ) -> Result<InstructionProof<Hasher>, ProofError> {
        let code_merkle = &self.code_merkle;

        let inst_proof = self.engine().make_inst_proof(
            self.as_context(),
            InstProofParams {
                current_pc,
                instance_merkle,
                code_merkle,
            },
            self.instance,
        )?;

        Ok(inst_proof)
    }

    fn engine(&self) -> &Engine {
        self.store.engine()
    }
}
