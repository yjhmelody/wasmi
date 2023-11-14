use accel_merkle::{DefaultMemoryConfig, MerkleKeccak256};
use codec::{Decode, Encode};
use wasmi::{
    osp::ExecError,
    proof::Status,
    snapshot::*,
    AsContextMut,
    Engine,
    Error,
    Extern,
    Instance,
    Linker,
    Module,
    StepResult,
    Store,
};
use wasmi_core::Value;

type Config = DefaultMemoryConfig<MerkleKeccak256>;

fn setup_module<T>(store: &mut Store<T>, wat: impl AsRef<str>) -> Result<Module, Error> {
    let wasm = wat::parse_str(wat).expect("Illegal wat");
    Module::new(store.engine(), &mut &wasm[..])
}

fn instantiate<T>(store: &mut Store<T>, module: &Module) -> Result<Instance, Error> {
    let linker = <Linker<T>>::new();
    let pre = linker.instantiate(store.as_context_mut(), module)?;
    let instance = pre.ensure_no_start(store.as_context_mut())?;
    Ok(instance)
}

fn call_step<T>(
    store: &mut Store<T>,
    instance: Instance,
    name: &str,
    inputs: &[Value],
    outputs: &mut [Value],
    n: &mut u64,
) -> Result<StepResult<()>, Error> {
    let f = instance
        .get_export(store.as_context_mut(), name)
        .and_then(Extern::into_func)
        .expect("Could find export function");

    f.step_call(store.as_context_mut(), inputs, outputs, Some(n))
}

#[test]
fn last_return_inst_call_stack_proof_should_work() {
    let wat = r#"
(module
  (func (export "add") (param $x i32) (param $y i32) (result i32) (i32.add (local.get $x) (local.get $y)))
)
    "#;
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());
    let module = setup_module(&mut store, wat).unwrap();
    let instance = instantiate(&mut store, &module).unwrap();

    let code_merkle = store
        .merkle_builder::<DefaultMemoryConfig<MerkleKeccak256>>(instance)
        .make_code_merkle();

    let inputs = vec![Value::I32(1), Value::I32(2)];
    let mut outputs = vec![Value::I32(0)];

    // total 4 steps
    let mut steps = 3;
    let res = call_step(
        &mut store,
        instance,
        "add",
        &inputs,
        &mut outputs,
        &mut steps,
    )
    .unwrap();

    assert_run_out_of_step(&res);

    unsafe {
        dbg!(&engine.current_inst().map(|i| *i.get()));
    }
    dbg!(&engine.current_pc());

    let merkle_builder = store.merkle_builder::<Config>(instance);
    let merkle = merkle_builder.build();

    let mut state_proof = merkle.make_state_proof(&store, Status::Running);
    let inst_proof = merkle.make_inst_proof(&store).unwrap();
    state_proof
        .run(&merkle.code_merkle.code_proof(), &inst_proof)
        .unwrap();

    // reset state
    engine.clear();

    // total 4 steps
    let mut steps = 4;
    call_step(
        &mut store,
        instance,
        "add",
        &inputs,
        &mut outputs,
        &mut steps,
    )
    .unwrap();

    unsafe {
        dbg!(&engine.current_inst().map(|i| *i.get()));
    }
    dbg!(&engine.current_pc());

    let merkle_builder = store.merkle_builder::<Config>(instance);
    let merkle = merkle_builder.build();

    let mut state_proof = merkle.make_state_proof(&store, Status::Finished);
    let inst_proof = merkle.make_inst_proof(&store).unwrap();
    // finished or trapped could not run anymore
    state_proof
        .run(&code_merkle.code_proof(), &inst_proof)
        .unwrap_err();
}

#[test]
fn test_finished_proof() {
    let wat = r#"
(module
  (func (export "finished") (param $x i32) (param $y i32) (result i32) (local.get $x))
)
    "#;
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());
    let module = setup_module(&mut store, wat).unwrap();
    let instance = instantiate(&mut store, &module).unwrap();

    let funcs = module
        .exports()
        .map(|exp| exp.name())
        .collect::<Vec<&str>>();

    const MAX_STEP: u64 = 1000_0000;
    for f in funcs {
        // 0. get expected result
        let mut expected_result = vec![Value::I32(0)];

        let inputs = vec![Value::I32(2), Value::I32(0)];
        let mut max_step = MAX_STEP;
        call_step(
            &mut store,
            instance,
            f,
            &inputs,
            &mut expected_result,
            &mut max_step,
        )
        .unwrap();

        let mut step = MAX_STEP - max_step;
        println!("function {:?} run {:?} steps", f, step);

        let mut result = vec![Value::I32(0)];
        call_step(&mut store, instance, f, &inputs, &mut result, &mut step).unwrap();

        // gen proof
        let code_merkle = store
            .merkle_builder::<DefaultMemoryConfig<MerkleKeccak256>>(instance)
            .make_code_merkle();

        let merkle_builder = store.merkle_builder::<Config>(instance);
        let merkle = merkle_builder.build();

        let mut state_proof = merkle.make_state_proof(&store, Status::Finished);
        let inst_proof = merkle.make_inst_proof(&store).unwrap();
        // finished or trapped could not run anymore
        state_proof
            .run(&code_merkle.code_proof(), &inst_proof)
            .unwrap_err();

        // finished or trapped could not run anymore
        let err = state_proof
            .run(&code_merkle.code_proof(), &inst_proof)
            .unwrap_err();
        assert!(matches!(err, ExecError::AlreadyFinished));
    }
}

#[test]
fn test_trapped_proof() {
    let wat = r#"
(module
  (func (export "div_s") (param $x i32) (param $y i32) (result i32) (i32.div_s (local.get $x) (local.get $y)))
  (func (export "div_u") (param $x i32) (param $y i32) (result i32) (i32.div_u (local.get $x) (local.get $y)))
  (func (export "trapped") (param $x i32) (param $y i32) (result i32) (unreachable))
)
    "#;
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());
    let module = setup_module(&mut store, wat).unwrap();
    let instance = instantiate(&mut store, &module).unwrap();

    let funcs = module
        .exports()
        .map(|exp| exp.name())
        .collect::<Vec<&str>>();

    const MAX_STEP: u64 = 1000_0000;
    for f in funcs {
        // 0. get expected result
        let mut expected_result = vec![Value::I32(0)];

        let inputs = vec![Value::I32(2), Value::I32(0)];
        let mut max_step = MAX_STEP;
        let err = call_step(
            &mut store,
            instance,
            f,
            &inputs,
            &mut expected_result,
            &mut max_step,
        )
        .unwrap_err();

        let mut step = MAX_STEP - max_step;
        println!("function {:?} run {:?} steps", f, step);
        assert!(matches!(err, Error::Trap(..)));

        let mut result = vec![Value::I32(0)];
        let err = call_step(&mut store, instance, f, &inputs, &mut result, &mut step).unwrap_err();
        assert!(matches!(err, Error::Trap(..)));

        // gen proof
        let code_merkle = store
            .merkle_builder::<DefaultMemoryConfig<MerkleKeccak256>>(instance)
            .make_code_merkle();

        let merkle_builder = store.merkle_builder::<Config>(instance);
        let merkle = merkle_builder.build();

        let mut state_proof = merkle.make_state_proof(&store, Status::Trapped);
        let inst_proof = merkle.make_inst_proof(&store).unwrap();
        // finished or trapped could not run anymore
        let err = state_proof
            .run(&code_merkle.code_proof(), &inst_proof)
            .unwrap_err();
        assert!(matches!(err, ExecError::AlreadyTrapped));
    }
}

// TODO: split the test into some small tests.
#[test]
fn test_snapshot_and_proof() {
    let wat = r#"
(module
  (global $g1 (mut i32) (i32.const 1))
  (global $g2 (mut i32) (i32.const 2))
  (global $g3 (mut i32) (i32.const 3))
  (func (export "foo") (param $x i32) (param $y i32) (result i32) (i32.add (local.get $x) (global.get $g3)))

  (func (export "add") (param $x i32) (param $y i32) (result i32) (i32.add (local.get $x) (local.get $y)))
  (func (export "sub") (param $x i32) (param $y i32) (result i32) (i32.sub (local.get $x) (local.get $y)))
  (func (export "mul") (param $x i32) (param $y i32) (result i32) (i32.mul (local.get $x) (local.get $y)))
  (func (export "div_s") (param $x i32) (param $y i32) (result i32) (i32.div_s (local.get $x) (local.get $y)))
  (func (export "div_u") (param $x i32) (param $y i32) (result i32) (i32.div_u (local.get $x) (local.get $y)))
  (func (export "rem_s") (param $x i32) (param $y i32) (result i32) (i32.rem_s (local.get $x) (local.get $y)))
  (func (export "rem_u") (param $x i32) (param $y i32) (result i32) (i32.rem_u (local.get $x) (local.get $y)))
  (func (export "and") (param $x i32) (param $y i32) (result i32) (i32.and (local.get $x) (local.get $y)))
  (func (export "or") (param $x i32) (param $y i32) (result i32) (i32.or (local.get $x) (local.get $y)))
  (func (export "xor") (param $x i32) (param $y i32) (result i32) (i32.xor (local.get $x) (local.get $y)))
  (func (export "shl") (param $x i32) (param $y i32) (result i32) (i32.shl (local.get $x) (local.get $y)))
  (func (export "shr_s") (param $x i32) (param $y i32) (result i32) (i32.shr_s (local.get $x) (local.get $y)))
  (func (export "shr_u") (param $x i32) (param $y i32) (result i32) (i32.shr_u (local.get $x) (local.get $y)))
  (func (export "rotl") (param $x i32) (param $y i32) (result i32) (i32.rotl (local.get $x) (local.get $y)))
  (func (export "rotr") (param $x i32) (param $y i32) (result i32) (i32.rotr (local.get $x) (local.get $y)))
  (func (export "eq") (param $x i32) (param $y i32) (result i32) (i32.eq (local.get $x) (local.get $y)))
  (func (export "ne") (param $x i32) (param $y i32) (result i32) (i32.ne (local.get $x) (local.get $y)))
  (func (export "lt_s") (param $x i32) (param $y i32) (result i32) (i32.lt_s (local.get $x) (local.get $y)))
  (func (export "lt_u") (param $x i32) (param $y i32) (result i32) (i32.lt_u (local.get $x) (local.get $y)))
  (func (export "le_s") (param $x i32) (param $y i32) (result i32) (i32.le_s (local.get $x) (local.get $y)))
  (func (export "le_u") (param $x i32) (param $y i32) (result i32) (i32.le_u (local.get $x) (local.get $y)))
  (func (export "gt_s") (param $x i32) (param $y i32) (result i32) (i32.gt_s (local.get $x) (local.get $y)))
  (func (export "gt_u") (param $x i32) (param $y i32) (result i32) (i32.gt_u (local.get $x) (local.get $y)))
  (func (export "ge_s") (param $x i32) (param $y i32) (result i32) (i32.ge_s (local.get $x) (local.get $y)))
  (func (export "ge_u") (param $x i32) (param $y i32) (result i32) (i32.ge_u (local.get $x) (local.get $y)))
)
    "#;
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());
    let module = setup_module(&mut store, wat).unwrap();
    let instance = instantiate(&mut store, &module).unwrap();

    let funcs = module
        .exports()
        .map(|exp| exp.name())
        .collect::<Vec<&str>>();

    const MAX_STEP: u64 = 1000_0000;
    for f in funcs {
        // 0. get expected result
        let mut expected_result = vec![Value::I32(0)];

        let inputs = vec![Value::I32(1), Value::I32(2)];
        let mut max_step = MAX_STEP;
        let res = call_step(
            &mut store,
            instance,
            f,
            &inputs,
            &mut expected_result,
            &mut max_step,
        )
        .unwrap();
        println!("function {:?} run {:?} steps", f, MAX_STEP - max_step,);

        assert!(matches!(res, StepResult::Results(..)));

        engine.clear();
        assert_eq!(engine.current_pc(), None);
        let mut result = vec![Value::I32(0)];
        // 1. only input params
        let res = call_step(&mut store, instance, f, &inputs, &mut result, &mut 0).unwrap();
        assert!(matches!(engine.current_pc(), Some(..)));
        assert_run_out_of_step(&res);

        // 2. make snapshot for instance.
        let snapshot_instance = store.snapshot().make_instance(instance).encode();
        // 3. make snapshot for engine.
        let snapshot_engine = store.snapshot().make_engine().encode();

        // 4. decode snapshots
        let snapshot_instance = InstanceSnapshot::decode(&mut &snapshot_instance[..]).unwrap();
        let snapshot_engine = EngineSnapshot::decode(&mut &snapshot_engine[..]).unwrap();

        let code_merkle = store
            .merkle_builder::<DefaultMemoryConfig<MerkleKeccak256>>(instance)
            .make_code_merkle();
        let code_proof = code_merkle.code_proof();

        let merkle_builder = store.merkle_builder::<Config>(instance);
        let merkle = merkle_builder.build();

        let mut state_proof_1 = merkle.make_state_proof(&store, Status::Running);
        let inst_proof_1 = merkle.make_inst_proof(&store).unwrap();

        // creates new engine/store
        let engine = Engine::default();
        let mut store = Store::new(&engine, ());
        let module = setup_module(&mut store, wat).unwrap();
        // 5. restore instance and engine from snapshot by instance.
        let linker = <Linker<()>>::new();
        let instance = store
            .snapshot()
            .restore(&linker, &module, snapshot_instance, &snapshot_engine)
            .unwrap();

        let mut result = vec![Value::I32(0)];

        let merkle_builder = store.merkle_builder::<Config>(instance);
        let merkle = merkle_builder.build();
        let state_proof_2 = merkle.make_state_proof(&store, Status::Running);

        // ensure two instance have the same proof in the first step.
        assert_eq!(state_proof_1, state_proof_2);

        let current_pc = engine.current_pc().unwrap();
        // run one step.
        let res = engine
            .resume_execute_step(store.as_context_mut(), instance, Some(1).as_mut())
            .unwrap();
        assert_run_out_of_step(&res);

        assert_eq!(current_pc + 1, engine.current_pc().unwrap());

        let merkle_builder = store.merkle_builder::<Config>(instance);
        let merkle = merkle_builder.build();
        let state_proof_3 = merkle.make_state_proof(&store, Status::Running);

        state_proof_1.run(&code_proof, &inst_proof_1).unwrap();
        let state_proof_hash_1 = state_proof_1.hash();
        let proof_hash_3 = state_proof_3.hash();
        // ensure hash(osp(proof1)) == hash(proof3)
        assert_eq!(state_proof_hash_1, proof_hash_3);

        engine
            .resume_execute_step_with_result(
                store.as_context_mut(),
                instance,
                &mut result[..],
                None,
            )
            .unwrap();

        assert_eq!(result, expected_result, "`{}` failed", f);

        assert!(matches!(engine.current_pc(), Some(..)));

        let mut result2 = vec![Value::I32(i32::MAX)];
        engine
            .resume_execute_step_with_result(
                store.as_context_mut(),
                instance,
                &mut result2[..],
                Some(&mut 0),
            )
            .unwrap();

        // This function is not a reentrant function.
        assert_ne!(result2, expected_result, "`{}` failed", f);
    }
}

fn assert_run_out_of_step(res: &StepResult<()>) {
    match res {
        StepResult::Results(()) => unreachable!(),
        StepResult::RunOutOfStep => {}
    }
}
