use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use ff::{Field, PrimeField};
use rand_core::OsRng;

pub enum DomainSeparator {
    HASH,
    COMMITMENT,
    SIGNATURE,
    PRF,
}

impl DomainSeparator {
    pub fn value(&self) -> u32 {
        match *self {
            DomainSeparator::HASH => 0,
            DomainSeparator::COMMITMENT => 1,
            DomainSeparator::SIGNATURE => 2,
            DomainSeparator::PRF => 3,
        }
    }

    pub fn from(value: u32) -> DomainSeparator {
        match value {
            0 => DomainSeparator::HASH,
            1 => DomainSeparator::COMMITMENT,
            2 => DomainSeparator::SIGNATURE,
            3 => DomainSeparator::PRF,
            _ => panic!("Can't get domain separator from value: {}", value)
        }
    }
}

pub fn rand_field<F: PrimeField>() -> F {
    let mut csprng: OsRng = OsRng;
    return <F as Field>::random(&mut csprng);
}

pub fn bits_to_field<F: PrimeField>(le_bits: [bool; 256]) -> F {
    let mut mult = F::ONE;
    let mut val = F::ZERO;
    for bit in le_bits {
        if bit {
            val += mult;
        }
        mult = mult + mult;
    }
    val
}

pub fn hex_str<F: PrimeField>(field: F) -> String {
    hex_string_from(field.to_repr().as_ref())
}

pub fn root_abs_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let abs_path = Path::new(manifest_dir);
    abs_path.to_str().unwrap().to_owned()
}

pub fn run_shell_script(script_path: &str, args: Option<Vec<String>>) -> String {
    let mut sh_args: Vec<String> = vec![script_path.parse().unwrap()];
    if args.is_some() {
        sh_args.extend(args.unwrap());
    }

    let mut child = Command::new("zsh")
        .args(sh_args)
        .stdout(Stdio::piped()) // Capture the stdout
        .spawn()
        .expect("Failed to execute script");

    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => panic!("Failed to capture stdout"),
    };

    let mut output = String::new();
    match stdout.read_to_string(&mut output) {
        Ok(_) => println!("Script output:\n{}", output),
        Err(e) => panic!("Failed to read stdout: {}", e),
    }
    output
}

pub fn run_python_script(path: &str, args: Vec<String>) {
    let mut py_args: Vec<String> = vec![path.parse().unwrap()];
    py_args.extend(args);

    let mut py_output = Command::new("python3")
        .args(py_args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute python script");

    let mut py_std_out = match py_output.stdout.take() {
        Some(stdout) => stdout,
        None => panic!("Failed to capture stdout"),
    };

    let mut output = String::new();
    match py_std_out.read_to_string(&mut output) {
        Ok(_) => println!("{}", output),
        Err(e) => panic!("Failed to read stdout: {}", e),
    }
}

pub fn hex_string_from(bytes: &[u8]) -> String {
    assert_eq!(bytes.len(), 32);
    let strs: Vec<String> = bytes.into_iter()
        .map(|byte| format!("{:x}", byte))
        .collect();
    format!("[{}]", strs.join(", "))
}