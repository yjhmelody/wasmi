use accel_merkle::MerkleKeccak256;
use codec::{Decode, Encode};
use wasmi::{
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
    n: Option<&mut u64>,
) -> Result<StepResult<()>, Error> {
    let f = instance
        .get_export(store.as_context_mut(), name)
        .and_then(Extern::into_func)
        .expect("Could find export function");

    f.step_call(store.as_context_mut(), inputs, outputs, n)
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
        let mut max_step = Some(MAX_STEP);
        let res = call_step(
            &mut store,
            instance,
            f,
            &inputs,
            &mut expected_result,
            max_step.as_mut(),
        )
        .unwrap();
        println!(
            "function {:?} run {:?} steps",
            f,
            max_step.map(|s| MAX_STEP - s)
        );

        match res {
            StepResult::Results(()) => {}
            StepResult::RunOutOfStep(_pc) => unreachable!(),
        }

        let mut result = vec![Value::I32(0)];
        // 1. only run one instruction
        let mut one_step = Some(1);
        let res = call_step(
            &mut store,
            instance,
            f,
            &inputs,
            &mut result,
            one_step.as_mut(),
        )
        .unwrap();
        drop(result);

        let pc = match res {
            StepResult::Results(()) => unreachable!(),
            StepResult::RunOutOfStep(pc) => pc,
        };

        // 2. make snapshot for instance.
        let snapshot_instance = store.snapshot().make_instance(instance).encode();
        // 3. make snapshot for engine.
        let snapshot_engine = store.snapshot().make_engine().encode();

        // 4. decode snapshots
        let snapshot_instance = InstanceSnapshot::decode(&mut &snapshot_instance[..]).unwrap();
        let snapshot_engine = EngineSnapshot::decode(&mut &snapshot_engine[..]).unwrap();

        let code_merkle = store
            .code_proof::<MerkleKeccak256>(instance)
            .make_code_merkle();

        let mut proof = store
            .osp_proof::<MerkleKeccak256>(&code_merkle, instance)
            .make_osp_proof_v0(pc)
            .unwrap();
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

        let proof2 = store
            .osp_proof::<MerkleKeccak256>(&code_merkle, instance)
            .make_osp_proof_v0(pc)
            .unwrap();
        // ensure two instance have the same proof in the first step.
        assert_eq!(proof, proof2);

        // step one.
        engine
            .execute_step_at_pc(
                store.as_context_mut(),
                pc as usize,
                instance,
                Some(1).as_mut(),
            )
            .unwrap();

        let code_proof = code_merkle.code_proof();
        let proof3 = store
            .osp_proof::<MerkleKeccak256>(&code_merkle, instance)
            .make_osp_proof_v0(pc + 1)
            .unwrap();

        proof.run(&code_proof).unwrap();

        let proof_hash_1 = proof.hash();
        let proof_hash_3 = proof3.hash();
        // ensure osp proof equal to proof generated by `execute_step_at_pc`.
        assert_eq!(proof_hash_1, proof_hash_3);

        // 6. run engine using previous pc.
        // we should use the restored instance.
        engine
            .execute_step_at_pc_with_result(
                store.as_context_mut(),
                // we know the next step is here.
                pc as usize + 1,
                instance,
                &mut result[..],
                None,
            )
            .unwrap();

        assert_eq!(expected_result, result, "`{}` failed", f);
    }
}
