use crate::{
    snapshot::{EngineSnapshot, InstanceSnapshot},
    AsContext,
    AsContextMut,
    Engine,
    Error,
    Instance,
    Linker,
    Module,
    Store,
    StoreContext,
    StoreContextMut,
};

/// A builder for creating snapshot by store.
pub struct SnapshotBuilder<'a, T> {
    pub(crate) store: &'a mut Store<T>,
}

impl<'a, T> AsContext for SnapshotBuilder<'a, T> {
    type UserState = T;

    #[inline]
    fn as_context(&self) -> StoreContext<'_, Self::UserState> {
        StoreContext {
            store: &*self.store,
        }
    }
}

impl<'a, T> AsContextMut for SnapshotBuilder<'a, T> {
    #[inline]
    fn as_context_mut(&mut self) -> StoreContextMut<'_, Self::UserState> {
        StoreContextMut { store: self.store }
    }
}

impl<'a, T> SnapshotBuilder<'a, T> {
    /// Make a module level instance snapshot.
    pub fn make_instance(&self, instance: Instance) -> InstanceSnapshot {
        let entity_index = self.store.unwrap_index(instance.into_inner());
        let entity = self.store.instances.get(entity_index).unwrap_or_else(|| {
            panic!(
                "the store has no reference to the given instance: {:?}",
                instance,
            )
        });
        entity.make_snapshot(self, self.engine().clone())
    }

    /// Make a engine level snapshot.
    pub fn make_engine(&self) -> EngineSnapshot {
        self.engine().lock().make_snapshot()
    }

    /// Restores `store` from some snapshots according to linker and module.
    ///
    /// # Notes
    ///
    /// The module and linker must be consistent with the snapshots.
    pub fn restore(
        &mut self,
        linker: &Linker<T>,
        module: &Module,
        instance: InstanceSnapshot,
        engine: &EngineSnapshot,
    ) -> Result<Instance, Error> {
        let pre = linker.restore_instance(self.as_context_mut(), module, instance)?;
        let instance = pre.no_start(self.as_context_mut());
        self.restore_engine(engine, instance)?;
        Ok(instance)
    }

    /// Restores engine from snapshot from instance.
    ///
    /// # Notes
    ///
    /// The instance must be consistent with the snapshot.
    pub fn restore_engine(
        &mut self,
        snapshot: &EngineSnapshot,
        instance: Instance,
    ) -> Result<(), Error> {
        self.engine().lock().restore_engine(snapshot, instance)?;
        Ok(())
    }

    fn engine(&self) -> &Engine {
        self.store.engine()
    }
}
