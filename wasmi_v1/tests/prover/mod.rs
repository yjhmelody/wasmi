use assert_matches::assert_matches;
use codec::{Decode, Encode};
use wasmi::{errors::InstantiationError, *};
use wasmi_core::{Trap, TrapInner, Value};

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

fn call_step_n<T>(
    store: &mut Store<T>,
    instance: Instance,
    name: &str,
    inputs: &[Value],
    outputs: &mut [Value],
    n: Option<u64>,
) -> Result<(), Error> {
    let f = instance
        .get_export(store.as_context_mut(), name)
        .and_then(Extern::into_func)
        .expect("Could find export function");

    f.call_step_n(store.as_context_mut(), inputs, outputs, n)
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
    let instance = instantiate(&mut store, &module).unwrap();
    let one_step = Some(1);

    let funcs = module
        .exports()
        .map(|exp| exp.name())
        .collect::<Vec<&str>>();

    for f in funcs {
        let mut expected_result = vec![Value::I32(0)];

        // 0. get expected result
        call_step_n(
            &mut store,
            instance,
            f,
            &vec![Value::I32(1), Value::I32(2)],
            &mut expected_result,
            None,
        )
        .unwrap();

        let mut result = vec![Value::I32(0)];
        // 1. only run one instruction
        let err = call_step_n(
            &mut store,
            instance,
            f,
            &vec![Value::I32(1), Value::I32(2)],
            &mut result,
            one_step,
        )
        .unwrap_err();
        // must meet halt
        assert_halt(err);
        // 2. make snapshot for instance.
        let snapshot = instance.make_snapshot(&store);
        let snapshot_bytes = snapshot.encode();
        // 3. decode snapshot
        let snapshot = InstanceSnapshot::decode(&mut &snapshot_bytes[..]).unwrap();
        let mut linker = Linker::<()>::new();
        // 4. restore instance from snapshot
        let instance = linker
            .restore_instance(store.as_context_mut(), &module, snapshot)
            .unwrap()
            .ensure_no_start(store.as_context_mut())
            .unwrap();

        // 5. run the rest instructions
        call_step_n(
            &mut store,
            instance,
            f,
            &vec![Value::I32(1), Value::I32(2)],
            &mut result,
            None,
        )
        .unwrap();

        assert_eq!(expected_result, result, "`{}` failed", f);
    }
}

fn assert_halt(err: Error) {
    match err {
        Error::Trap(trap) if trap.is_halt() => {}
        _ => panic!("Error must be trap halt"),
    }
}
