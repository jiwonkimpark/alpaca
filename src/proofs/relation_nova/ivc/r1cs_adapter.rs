use std::collections::HashMap;
use std::marker::PhantomData;
use bellpepper_core::{ConstraintSystem, LinearCombination, Variable};
use bellpepper_core::num::AllocatedNum;
use circ::target::r1cs::{Lc, R1csFinal, Var, VarType};
use circ::target::r1cs::spartan_opt::read_r1cs_final;
use circ_fields::FieldV;
use ff::{Field, PrimeField};
use fxhash::FxHashMap;
use gmp_mpfr_sys::gmp::limb_t;
use lazy_static::lazy_static;
use rayon::prelude::*;
use rug::Integer;
use crate::errors::AnonymousBlocklistError;
use crate::util::root_abs_path;

pub struct R1CSAdapter<F> {
    _p: PhantomData<F>,
}

lazy_static! {
    pub static ref IVC_R1CS: R1csFinal = read_r1cs_final(root_abs_path() + "/IVC_R1CS").unwrap();
}
impl<F: PrimeField> R1CSAdapter<F> {
    /// Gets linear combinations
    /// Arguments
    /// * `r1cs`: the R1CS instance information obtained from circ
    /// * `values`: the map between var (index and variable type) to the corresponding field value obtained from circ
    /// * `cs`: the constraint system that are used for the circuit
    ///
    /// Returns
    /// the linear combinations (A, B, C) in bellpepper_core's representation
    pub(crate) fn linear_combinations<CS>(
        values: &Vec<FieldV>,
        cs: &mut CS,
        namespace: String,
    ) -> Vec<(LinearCombination<F>, LinearCombination<F>, LinearCombination<F>)>
        where
            CS: ConstraintSystem<F>
    {
        let vars = Self::map_circ_to_bellpepper_vars(&IVC_R1CS.vars, &IVC_R1CS.names, values, cs, namespace).unwrap();
        IVC_R1CS.constraints
            .par_iter()
            .map(|(a, b, c)| {
                (
                    Self::convert_linear_combination::<CS>(&vars, a),
                    Self::convert_linear_combination::<CS>(&vars, b),
                    Self::convert_linear_combination::<CS>(&vars, c)
                )
            })
            .collect()
    }

    /// Maps the variables in CirC to that in bellpepper_core.
    /// This function will be used to convert CirC's linear combination to bellpepper_core's linear_combination
    /// Arguments
    /// * `r1cs`: the R1CS instance information obtained from circ
    /// * `values`: the map between var (index and variable type) to the corresponding field value obtained from circ
    /// * `cs`: the constraint system that are used for the circuit
    ///
    /// Returns
    /// the map between circ's variable to bellpepper_core's variable representation
    fn map_circ_to_bellpepper_vars<CS>(
        r1cs_vars: &Vec<Var>,
        r1cs_names: &FxHashMap<Var, String>,
        values: &Vec<FieldV>,
        cs: &mut CS,
        namespace: String
    ) -> Result<HashMap<Var, AllocatedNum<F>>, AnonymousBlocklistError>
        where
            CS: ConstraintSystem<F>
    {
        let mut circ_to_bellpepper_vars = HashMap::with_capacity(r1cs_vars.len());

        for (i, var) in r1cs_vars.iter().enumerate() {
            let name = r1cs_names.get(&var).unwrap();
            let name_fn = || format!("{namespace:?}_{name:?}");

            let alloc_fn = || {
                Ok({
                    let val = values.get(i).unwrap();
                    let f_val = Self::int_to_scalar(&val.i());
                    f_val
                })
            };
            let variable = match var.ty() {
                VarType::Inst => {
                    // Nova throws InvalidStepCircuitIO if allocate as input
                    AllocatedNum::alloc(cs.namespace(name_fn), alloc_fn).unwrap()
                }
                VarType::FinalWit => {
                    AllocatedNum::alloc(cs.namespace(name_fn), alloc_fn).unwrap()
                }
                _ => { return Err(AnonymousBlocklistError::InvalidParameter); }
            };
            circ_to_bellpepper_vars.insert(*var, variable);
        }

        return Ok(circ_to_bellpepper_vars);
    }

    /// Converts CirC's linear combination representation to bellpepper_core's linear combination representation
    /// Arguments
    /// * `vars_map`: the map between circ's variable to bellpepper_core's variable representation
    /// * `circ_lc`: the linear combination in circ's `Lc` data structure
    ///
    /// Returns
    /// the linear combination in bellpepper's `LinearCombination` data structure
    fn convert_linear_combination<CS: ConstraintSystem<F>>(
        vars_map: &HashMap<Var, AllocatedNum<F>>,
        circ_lc: &Lc,
    ) -> LinearCombination<F> {
        let mut lc_bellpepper = LinearCombination::<F>::zero();

        if !circ_lc.constant.is_zero() {
            lc_bellpepper = lc_bellpepper.add_unsimplified((Self::int_to_scalar(&circ_lc.constant.i()), CS::one()));
        }

        for (var, coeff) in &circ_lc.monomials {
            if !coeff.is_zero() {
                let variable = vars_map.get(var).unwrap().get_variable();
                lc_bellpepper = lc_bellpepper.add_unsimplified((Self::int_to_scalar(&coeff.i()), variable));
            }
        }

        lc_bellpepper
    }

    fn int_to_scalar(i: &Integer) -> F {
        let mut accumulator = F::ZERO;
        let limb_bits = (std::mem::size_of::<limb_t>() as u64) << 3;
        assert_eq!(limb_bits, 64);

        let two: u64 = 2;
        let mut m = F::from(two.pow(63));
        m *= F::from(two);

        // as_ref yields a least-significant-first array.
        for digit in i.as_ref().iter().rev() {
            accumulator *= m;
            accumulator += F::from(*digit);
        }
        accumulator
    }
}
