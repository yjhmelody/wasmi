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
use wasmi_core::{Value};

fn setup_module<T>(store: &mut Store<T>, wat: impl AsRef<str>) -> Result<Module, Error> {
    let wasm = wat::parse_str(wat).expect("Illegal wat");
    Module::new(store.engine(), &mut &wasm[..])
}

fn instantiate<T>(store: &mut Store<T>, module: &Module) -> Result<Instance, Error> {
    let mut linker = <Linker<T>>::new();
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
    n: Option<u64>,
) -> Result<StepResult<()>, Error> {
    let f = instance
        .get_export(store.as_context_mut(), name)
        .and_then(Extern::into_func)
        .expect("Could find export function");

    f.call_step(store.as_context_mut(), inputs, outputs, n)
}

#[test]
fn test_snapshot() {
    let wat = r#"
(module
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
    let one_step = Some(2);

    let funcs = module
        .exports()
        .map(|exp| exp.name())
        .collect::<Vec<&str>>();

    for f in funcs {
        let mut expected_result = vec![Value::I32(0)];

        // 0. get expected result
        let instance = instantiate(&mut store, &module).unwrap();

        let res = call_step(
            &mut store,
            instance,
            f,
            &vec![Value::I32(1), Value::I32(2)],
            &mut expected_result,
            None,
        )
        .unwrap();

        println!("expected_result: {:?}", expected_result);

        match res {
            StepResult::Results(()) => {}
            StepResult::RunOutOfStep(_pc) => unreachable!(),
        }

        let mut result = vec![Value::I32(0)];
        // 1. only run one instruction
        let res = call_step(
            &mut store,
            instance,
            f,
            &vec![Value::I32(1), Value::I32(2)],
            &mut result,
            one_step,
        )
        .unwrap();

        // println!("res: {:?}", res);

        let pc = match res {
            StepResult::Results(()) => unreachable!(),
            StepResult::RunOutOfStep(pc) => pc,
        };
        // println!("pc: {}", pc);

        // 2. make snapshot for instance.
        let snapshot_instance = store.make_instance_snapshot(instance).encode();
        // 3. make snapshot for engine.
        let snapshot_engine = store.make_engine_snapshot().encode();

        // 4. decode snapshots
        let snapshot_instance = InstanceSnapshot::decode(&mut &snapshot_instance[..]).unwrap();
        let snapshot_engine = EngineSnapshot::decode(&mut &snapshot_engine[..]).unwrap();

        let mut linker = Linker::<()>::new();
        // 5. restore instance from snapshot
        let instance = linker
            .restore_instance(store.as_context_mut(), &module, snapshot_instance)
            .unwrap()
            .ensure_no_start(store.as_context_mut())
            .unwrap();
        // 6. restore engine from snapshot
        store.make_engine_snapshot()

        // println!("instance: {:?}", instance);

        engine
            .execute_step_at_pc(store.as_context_mut(), pc as usize, instance, None)
            .unwrap();

        // // 5. run the instructions
        // call_step_n(
        //     &mut store,
        //     instance,
        //     f,
        //     &vec![Value::I32(1), Value::I32(2)],
        //     &mut result,
        //     None,
        // )
        // .unwrap();
        //
        // assert_eq!(expected_result, result, "`{}` failed", f);
    }
}
