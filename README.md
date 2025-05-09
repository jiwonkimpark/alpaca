# ALPACA: Anonymous Blocklisting with Constant-Sized Updatable Proofs
ALPACA is an anonymous blocklisting scheme that achieves constant online prover time, proof size, and verifier time. This is the Rust implementation of this paper, which will appear at IEEE S&P 2025. [The paper](https://eprint.iacr.org/2025/767) provides the details of the ALPACA design and formal proofs of security.

## Running the code
To run the code, you need to clone two repositories: this repository and [circ-alpaca](https://github.com/jiwonkimpark/circ-alpaca) under this repository (`circ-alpaca` is the fork of [circ compiler](https://github.com/circify/circ) that further implements proving and verifying functionalities necessary for ALPACA). The file tree should look like:
```
alpaca
├── circ-alpaca
├── examples
├── src
│   ├── hash
│   ├── proofs
│   ├── traits
│   ├── ...
├── Cargo.lock
├── Cargo.toml
└── README.md
```

### Building circ-compiler
You first need to build the circ-compiler. The procedure differs depending on which processor you use.
#### With Apple Silicon processors
* Move to `circ-alpaca`
  ```
  cd circ-alpaca
  ```
* Install dependencies
  ```
  brew tap coin-or-tools/coinor
  brew install coin-or-tools/coinor/cbc
  
  brew tap cvc5/homebrew-cvc5 
  brew install cvc5 
  ```
  If installing cvc5 using homebrew doesn't work, you can alternatively install cvc5 through the [cvc5 Github repo](https://github.com/cvc5/cvc5). After cloning the project, move to cvc5 directory and run the following:
  ```
  ./configure.sh --auto-download 
  cd build
  make
  make check
  make install
  ```
* Change the environment variable
  
  You need to set the environment variable so that circ compiler uses cvc5.
  ```
  export RSMT2_CVC4_CMD="path/to/your/cvc5"
  ```
* Build circ compiler
  ```
  cargo build --release --features r1cs,zok,spartan --example zk
  cargo build --release --features r1cs,zok,spartan --example circ
  ```

#### Other precessors
```
cd circ-alpaca
./scripts/dependencies_{your_os}.sh  # install dependencies; check which file you need to run
cargo build --release --features r1cs,zok,spartan --example zk
cargo build --release --features r1cs,zok,spartan --example circ
```

### Run ALPACA example
If you built the circ compiler successfully, you can now run an example of `alpaca`. The following command moves back to `alpaca` and run the example.
```
cd .. # move back to alpaca
cargo run --release --example example
```
