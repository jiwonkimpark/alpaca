use ff::PrimeField;
use crate::hash::constants::ROUND_CONSTANTS_LE_BITS;
use crate::hash::mds::MDS_LE_BITS;
use crate::util::bits_to_field;

pub struct Permutation<F>
    where
        F: PrimeField
{
    rate: usize,
    round_constants: Vec<F>,
    mds_matrix: Vec<Vec<F>>,
    full_round: usize,
    partial_round: usize,
}

impl<F> Permutation<F>
    where
        F: PrimeField
{
    pub fn new(
        rate: usize,
        full_round: usize,
        partial_round: usize,
    ) -> Self {
        Self {
            rate,
            round_constants: Self::round_constants(),
            mds_matrix: Self::mds_matrix(),
            full_round,
            partial_round,
        }
    }

    fn round_constants() -> Vec<F> {
        let le_bits = ROUND_CONSTANTS_LE_BITS;

        let mut fields_vec: Vec<F> = Vec::new();
        for le_bits in le_bits {
            let result = bits_to_field::<F>(le_bits);
            fields_vec.push(result);
        }

        assert_eq!(fields_vec.len(), 585);

        return fields_vec
    }
    fn mds_matrix() -> Vec<Vec<F>> {
        // We first obtained the mds matrix through Poseidon author's script for Fq (Scalar field for Pallas Curve)
        // and then generated le_bits_matrix through a script
        let le_bits_matrix = MDS_LE_BITS;

        let mut fields_matrix: Vec<Vec<F>> = Vec::new();
        for le_bits_vec in le_bits_matrix {
            let mut fields_vec: Vec<F> = Vec::new();
            for le_bits in le_bits_vec {
                let result = bits_to_field::<F>(le_bits);
                fields_vec.push(result)
            }
            fields_matrix.push(fields_vec);
        }

        return fields_matrix
    }

    pub(crate) fn permute(&self, state: Vec<F>) -> Vec<F> {
        let t = self.rate + 1;

        let mut result = state;
        for r in 0..self.full_round + self.partial_round {
            result = self.add_round_constants(result, r * t);
            result = self.sbox(result, r);
            result = self.mix_layer(result);
        }
        return result
    }

    fn add_round_constants(&self, mut state: Vec<F>, it: usize) -> Vec<F> {
        for i in 0..state.len() {
            state[i] += self.round_constants[it + i];
        }
        return state;
    }

    fn sbox(&self, mut state: Vec<F>, r: usize) -> Vec<F> {
        state[0] = state[0] * state[0] * state[0] * state[0] * state[0];
        for i in 1..state.len() {
            if r < self.full_round / 2 || r >= self.full_round / 2 + self.partial_round {
                state[i] = state[i] * state[i] * state[i] * state[i] * state[i];
            }
        }
        return state
    }

    fn mix_layer(&self, state: Vec<F>) -> Vec<F> {
        let mut mixed: Vec<F> = Vec::new();

        let n = state.len();
        for i in 0..n {
            let mut acc: F = F::ZERO;
            for j in 0..n {
                acc += state[j] * self.mds_matrix[i][j];
            }
            mixed.push(acc);
        }

        return mixed
    }
}

