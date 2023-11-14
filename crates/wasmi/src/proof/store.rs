use core::marker::PhantomData;

use accel_merkle::MerkleConfig;

use crate::{
    engine::ProofError,
    proof::{CodeMerkle, InstanceMerkle, InstructionProof, Status, WasmStateProof},
    AsContext,
    Engine,
    Instance,
    InstanceEntity,
    Store,
    StoreContext,
};

/// A builder for creating different kinds of merkle tree by store.
#[derive(Debug)]
pub struct ProofBuilder<'a, T, Config: MerkleConfig> {
    pub(crate) builder: MerkleBuilder<'a, T, Config>,
}

impl<'a, T, Config: MerkleConfig> AsContext for ProofBuilder<'a, T, Config> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext {
            store: self.builder.store,
        }
    }
}

/// The contains a static code merkle and a current wasm state instance merkle.
#[derive(Debug)]
pub struct WasmMerkle<Config: MerkleConfig> {
    pub instance: Instance,
    /// The code merkle tree.
    pub code_merkle: CodeMerkle<Config::Hasher>,
    /// The instance wasm state merkle tree.
    pub instance_merkle: InstanceMerkle<Config>,
}

impl<Config: MerkleConfig> WasmMerkle<Config> {
    /// Generate an instruction proof according to params.
    ///
    /// # Note
    ///
    /// - The current pc must be valid.
    /// - All merkle trees must belong to current engine state in logic.
    /// - Otherwise return proof error.
    pub fn make_inst_proof(
        &self,
        ctx: impl AsContext,
    ) -> Result<InstructionProof<Config>, ProofError> {
        ctx.as_context()
            .store
            .inst_proof(self.instance)
            .build(&self.code_merkle, &self.instance_merkle)
    }

    /// Create a state proof according to instance merkle and current pc.
    ///
    /// # Note
    ///
    /// - User must tell the right status of current call (running/finished/trapped).
    /// - The merkle must be corresponding to the current wasm state.
    pub fn make_state_proof(&self, ctx: impl AsContext, status: Status) -> WasmStateProof<Config> {
        ctx.as_context()
            .store
            .state_proof(self.instance)
            .build(&self.instance_merkle, status)
    }
}

/// A builder for creating different kinds of merkle tree by store.
#[derive(Debug)]
pub struct MerkleBuilder<'a, T, Config: MerkleConfig> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance: Instance,
    pub(crate) instance_entity: &'a InstanceEntity,
    pub(crate) _hasher: PhantomData<Config>,
}

impl<'a, T, Config: MerkleConfig> AsContext for MerkleBuilder<'a, T, Config> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Config: MerkleConfig> MerkleBuilder<'a, T, Config> {
    /// Make a code merkle from the store entity.
    ///
    /// # Note
    ///
    /// It is used to avoid duplicated computing.
    pub fn make_code_merkle(&self) -> CodeMerkle<Config::Hasher> {
        CodeMerkle::<Config::Hasher>::generate(
            self.as_context(),
            self.instance_entity.funcs(),
            self.store.engine().clone(),
        )
    }

    /// Make an instance merkle from the store entity.
    ///
    /// # Note
    ///
    /// It is used to avoid duplicated computing.
    pub fn make_instance_merkle(&self) -> InstanceMerkle<Config> {
        let instance_snapshot = self
            .instance_entity
            .make_snapshot(self.as_context(), self.store.engine().clone());
        InstanceMerkle::generate(instance_snapshot)
    }

    /// Build all merkle trees from the store entity.
    ///
    /// # Note
    ///
    /// It is used to avoid duplicated computing.
    pub fn build(&self) -> WasmMerkle<Config> {
        WasmMerkle {
            instance: self.instance,
            code_merkle: self.make_code_merkle(),
            instance_merkle: self.make_instance_merkle(),
        }
    }
}

/// A builder for creating wasm state proof by store.
#[derive(Debug)]
pub struct StateProofBuilder<'a, T, Config: MerkleConfig> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance_entity: &'a InstanceEntity,
    pub(crate) _config: PhantomData<Config>,
}

impl<'a, T, Config: MerkleConfig> AsContext for StateProofBuilder<'a, T, Config> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Config: MerkleConfig> StateProofBuilder<'a, T, Config> {
    /// Create a state proof according to instance merkle and current pc.
    ///
    /// # Note
    ///
    /// - User must tell the right status of current call (running/finished/trapped).
    /// - The merkle must be corresponding to the current wasm state.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn build(
        &self,
        instance_merkle: &InstanceMerkle<Config>,
        status: Status,
    ) -> WasmStateProof<Config> {
        let inst = match status {
            Status::Running => {
                let ip = self
                    .engine()
                    .current_inst()
                    .expect("The instruction ptr must be legal; qed");
                unsafe { Some(*ip.get()) }
            }
            _ => None,
        };

        let engine_proof = self.engine().make_engine_proof::<Config::Hasher>(inst);

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

        let current_pc =
            self.engine()
                .current_pc()
                .expect("Osp proof could not be generated before actually run") as _;
        WasmStateProof::<Config> {
            status,
            current_pc,
            globals_root,
            table_roots,
            memory_roots,
            engine_proof,
        }
    }

    /// Creates instance merkle for current wasm state.
    pub fn make_instance_merkle(&self) -> InstanceMerkle<Config> {
        let instance_snapshot = self
            .instance_entity
            .make_snapshot(self.as_context(), self.engine().clone());
        InstanceMerkle::generate(instance_snapshot)
    }

    fn engine(&self) -> &Engine {
        self.store.engine()
    }
}

/// A builder for creating instruction proof by store.
#[derive(Debug)]
pub struct InstProofBuilder<'a, T, Config: MerkleConfig> {
    pub(crate) store: &'a Store<T>,
    pub(crate) instance: Instance,
    pub(crate) _config: PhantomData<Config>,
}

impl<'a, T, Config: MerkleConfig> AsContext for InstProofBuilder<'a, T, Config> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext { store: self.store }
    }
}

impl<'a, T, Config: MerkleConfig> InstProofBuilder<'a, T, Config> {
    /// Generate an instruction proof according to params.
    ///
    /// # Note
    ///
    /// - The current pc must be valid.
    /// - All merkle trees must belong to current engine state in logic.
    /// - Otherwise return proof error.
    pub fn build(
        &self,
        code_merkle: &CodeMerkle<Config::Hasher>,
        instance_merkle: &InstanceMerkle<Config>,
    ) -> Result<InstructionProof<Config>, ProofError> {
        let inst_proof = self.engine().make_inst_proof(
            self.as_context(),
            self.instance,
            code_merkle,
            instance_merkle,
        )?;

        Ok(inst_proof)
    }

    fn engine(&self) -> &Engine {
        self.store.engine()
    }
}
