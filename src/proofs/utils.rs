use std::sync::Arc;
use circ::ir::term::Value;
use circ_fields::FieldV;
use ff::PrimeField;
use fxhash::FxHashMap;
use rug::Integer;

const MODULAR: &str = "28948022309329048855892746252171976963363056481941647379679742748393362948097";

pub enum InputValue<'a, F: PrimeField> {
    Bytes(&'a [u8]),
    Field(F),
}
pub struct In<'a, F: PrimeField> {
    pub key: String,
    pub val: InputValue<'a, F>
}

impl<'a, F: PrimeField> In<'a, F> {
    pub fn new(key: &str, val: InputValue<'a, F>) -> Self {
        Self { key: key.parse().unwrap(), val }
    }
}

pub fn zok_input_map<F: PrimeField>(inputs: Vec<In<F>>) -> FxHashMap<String, Value> {
    let m = Integer::from_str_radix(
        MODULAR,
        10,
    ).unwrap();
    let m_arc = Arc::<Integer>::new(m);

    let mut in_map: FxHashMap<String, Value> = FxHashMap::default();

    for input in inputs {
        match input.val {
            InputValue::Field(f) => {
                in_map.insert(input.key, Value::Field(field_to_zok_field(f, &m_arc)));
            }
            InputValue::Bytes(bytes) => {
                in_map.insert(input.key, Value::Field(bytes_to_zok_field(bytes, &m_arc)));
            }
        }
    }

    in_map
}
pub fn bytes_to_zok_field(bytes: &[u8], modulus: &Arc<Integer>) -> FieldV {
    let hex_vec = {
        assert_eq!(bytes.len(), 32);

        let strs: Vec<String> = bytes.into_iter()
            .map(|byte| format!("{:x}", byte))
            .collect();
        strs
    };

    hex_vec_to_field_value(hex_vec, modulus)
}

pub fn field_to_zok_field<F: PrimeField>(field: F, modulus: &Arc<Integer>) -> FieldV {
    let hex_vec = {
        let repr = field.to_repr();
        let bytes = repr.as_ref();
        assert_eq!(bytes.len(), 32);

        let strs: Vec<String> = bytes.into_iter()
            .map(|byte| format!("{:x}", byte))
            .collect();
        strs
    };

    hex_vec_to_field_value(hex_vec, modulus)
}

fn hex_vec_to_field_value(hex_vec: Vec<String>, modulus: &Arc<Integer>) -> FieldV {
    let mut hex_str = String::new();
    for hex in hex_vec.iter().rev() {
        let tmp = hex.clone();
        let append_hex = match tmp.len() {
            1 => format!("0{}", tmp),
            _ => tmp,
        };
        hex_str = format!("{}{}", hex_str, append_hex);
    }

    let integer: Integer = Integer::from_str_radix(hex_str.as_str(), 16).unwrap();
    let field_value = FieldV::new::<Integer>(integer, modulus.clone());

    field_value
}
