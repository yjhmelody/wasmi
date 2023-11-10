use core::marker::PhantomData;

use accel_merkle::{MerkleConfig, MerkleHasher};

use crate::{
    engine::{InstProofParams, ProofError},
    proof::{CodeMerkle, InstanceMerkle, InstructionProof, OspProof, Status, VersionedOspProof},
    AsContext,
    Engine,
    Instance,
    InstanceEntity,
    Store,
    StoreContext,
};

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
pub struct OspProofBuilder<'a, T, Config: MerkleConfig> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance: Instance,
    pub(crate) instance_entity: &'a InstanceEntity,
    pub(crate) code_merkle: &'a CodeMerkle<Config::Hasher>,
}

impl<'a, T, Config: MerkleConfig> AsContext for OspProofBuilder<'a, T, Config> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Config: MerkleConfig> OspProofBuilder<'a, T, Config> {
    /// Creates the latest version osp proof data.
    pub fn make_osp_proof(&self) -> Result<VersionedOspProof<Config>, ProofError> {
        self.make_osp_proof_v0().map(VersionedOspProof::V0)
    }

    /// Creates an osp proof according to current pc.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn make_osp_proof_v0(&self) -> Result<OspProof<Config>, ProofError> {
        let instance_merkle = self.make_instance_merkle();
        let inst_proof = self.make_inst_proof(&instance_merkle)?;
        let engine_proof = self
            .engine()
            .make_engine_proof::<Config::Hasher>(inst_proof.inst);

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

        Ok(OspProof::<Config> {
            // TODO:
            status: Status::Running,
            globals_root,
            table_roots,
            memory_roots,
            engine_proof,
            inst_proof,
        })
    }

    /// Creates instance merkle for current wasm state.
    fn make_instance_merkle(&self) -> InstanceMerkle<Config> {
        let instance_snapshot = self
            .instance_entity
            .make_snapshot(self.as_context(), self.engine().clone());
        InstanceMerkle::generate(instance_snapshot)
    }

    /// Generate an instruction proof according to params.
    ///
    /// # Note
    ///
    /// - The current pc must be valid.
    /// - All merkle trees must belong to current engine state in logic.
    /// - Otherwise return proof error.
    pub fn make_inst_proof(
        &self,
        instance_merkle: &InstanceMerkle<Config>,
    ) -> Result<InstructionProof<Config>, ProofError> {
        let code_merkle = &self.code_merkle;

        let inst_proof = self.engine().make_inst_proof(
            self.as_context(),
            self.instance,
            InstProofParams {
                instance_merkle,
                code_merkle,
            },
        )?;

        Ok(inst_proof)
    }

    fn engine(&self) -> &Engine {
        self.store.engine()
    }
}
