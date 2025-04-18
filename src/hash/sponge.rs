use ff::PrimeField;
use crate::hash::permute::Permutation;
use crate::util::DomainSeparator;

pub struct Sponge<F: PrimeField>
    where
        F: PrimeField
{
    rate: usize,
    absorb_pos: usize,
    squeeze_pos: usize,
    perm: Permutation<F>,
}

impl<F: PrimeField> Sponge<F>
    where
        F: PrimeField
{
    pub fn new(rate: usize, full_round: usize, partial_round: usize) -> Self {
        Self {
            rate,
            absorb_pos: 0,
            squeeze_pos: 0,
            perm: Permutation::new(rate, full_round, partial_round),
        }
    }

    pub fn run(&mut self, inputs: Vec<F>, domain_separator: DomainSeparator) -> F {
        let t = self.rate + 1;
        let init_vector = self.init_state(t, inputs.len(), domain_separator);

        let absorbed = self.absorb(init_vector, inputs);
        let squeezed = self.squeeze(1, absorbed);

        return squeezed[0];
    }

    fn init_state(&mut self, state_size: usize, msg_length: usize, domain_separator: DomainSeparator) -> Vec<F> {
        let mut state: Vec<F> = vec![F::ZERO; state_size];

        let capacity_element = self.capacity_element(msg_length, domain_separator);
        state[0] = capacity_element;

        return state;
    }

    const HASHER_BASE: u128 = (0 - 159) as u128;

    fn capacity_element(&self, msg_length: usize, domain_separator: DomainSeparator) -> F {
        let left = Self::HASHER_BASE.overflowing_mul(msg_length as u128).0;
        let right = Self::HASHER_BASE.overflowing_mul(Self::HASHER_BASE).0
            .overflowing_mul(msg_length as u128).0
            .overflowing_mul(domain_separator.value() as u128).0;
        let cap_elem_u128 = left.overflowing_add(right).0;

        return F::from_u128(cap_elem_u128);
    }

    fn absorb(&mut self, init: Vec<F>, inputs: Vec<F>) -> Vec<F> {
        let mut state: Vec<F> = init;

        for input in inputs {
            if self.absorb_pos == self.rate {
                state = self.perm.permute(state.clone());
                self.absorb_pos = 0;
            }

            let old: F = state[self.absorb_pos + 1];
            let new = old + input;
            state[self.absorb_pos + 1] = new;
            self.absorb_pos += 1;
        }

        self.squeeze_pos = self.rate;

        return state;
    }

    fn squeeze(&mut self, output_len: usize, absorbed: Vec<F>) -> Vec<F> {
        let mut out = Vec::with_capacity(output_len);
        let mut state = absorbed;

        for _ in 0..output_len {
            if self.squeeze_pos == self.rate {
                state = self.perm.permute(state.clone());
                self.absorb_pos = 0;
                self.squeeze_pos = 0;
            }

            out.push(state[self.squeeze_pos]);
            self.squeeze_pos += 1;
        }

        return out;
    }
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use crate::curve::{PallasCurve, PastaCurve};
    use crate::hash::constants::ROUND_CONSTANTS_LE_BITS;
    use crate::hash::mds::MDS_LE_BITS;
    use crate::util::{bits_to_field, DomainSeparator};

    const HASHER_BASE: u128 = (0 - 159) as u128;

    #[test]
    fn all_capacity_elements_for() {
        all_capacity_elements::<<PallasCurve as PastaCurve>::Scalar>();
    }

    fn all_capacity_elements<F: PrimeField>() {
        let available_msg_lens = [1, 2, 3, 4, 5, 6, 7, 8];
        let available_domain_separators = [0, 1, 2, 3];

        let mut cap_elem_matrix: Vec<Vec<F>> = Vec::new();
        for msg_len in available_msg_lens {
            let mut cap_elem_vec: Vec<F> = Vec::new();
            for domain_separator in available_domain_separators {
                let cap_elem = get_capacity_element(msg_len, DomainSeparator::from(domain_separator));
                cap_elem_vec.push(cap_elem);
            }
            cap_elem_matrix.push(cap_elem_vec);
        }
        println!("{:?}", cap_elem_matrix);
    }

    fn get_capacity_element<F: PrimeField>(msg_length: usize, domain_separator: DomainSeparator) -> F {
        let left = HASHER_BASE.overflowing_mul(msg_length as u128).0;
        let right = HASHER_BASE.overflowing_mul(HASHER_BASE).0
            .overflowing_mul(msg_length as u128).0
            .overflowing_mul(domain_separator.value() as u128).0;
        let cap_elem_u128 = left.overflowing_add(right).0;

        return F::from_u128(cap_elem_u128);
    }

    #[test]
    fn test_with_Fq() {
        // hex_to_field::<<PallasCurve as PastaCurve>::Scalar>()
        mds::<<PallasCurve as PastaCurve>::Scalar>()
    }

    fn mds<F: PrimeField>() {
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

        print!("{:?}", fields_matrix)
    }

    fn round_constants<F: PrimeField>() {
        let le_bits_bool = ROUND_CONSTANTS_LE_BITS;

        let mut fields_vec: Vec<F> = Vec::new();
        for le_bits in le_bits_bool {
            let result = bits_to_field::<F>(le_bits);
            fields_vec.push(result);
        }
        assert_eq!(fields_vec.len(), 585);
    }
}