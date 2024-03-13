use super::ErrorReason;
use crate::bn_to_gen;
use crate::isprime;
use crate::pari_init;
use crate::primitives::is_prime;
use crate::primitives::numerical_log;
use crate::primitives::prng;
use crate::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Bls12_381_1, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;
use std::os::raw::c_int;

const SECURITY_PARAMETER: usize = 128;
const C: usize = 10;

/// Linearly homomorphic encryption scheme and a zkpok that a ciphertext encrypts a scalar x given
/// public Q = x G. interface includes:
/// keygen, encrypt, decrypt, prove, verify.
///
/// The encryption scheme is taken from https://eprint.iacr.org/2018/791.pdf Theorem 2
/// The zero knowledge proof is a non interactive version of the proof
/// given in  https://eprint.iacr.org/2019/503.pdf figure 8
///
/// In this implementation we use the LCM trick to make dl_cl proof faster. TODO: add reference

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PK {
    pub q: BigInt,
    pub delta_k: BigInt,
    pub delta_q: BigInt,
    pub gq: BinaryQF,
    pub h: BinaryQF,
    pub stilde: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HSMCL {
    pub sk: BigInt,
    pub pk: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLProof {
    pub pk: PK,
    pub ciphertext: Ciphertext,
    q: Point<Bls12_381_1>,
    t_vec: Vec<TTriplets>,
    u_vec: Vec<U1U2>,
}

pub struct Witness {
    pub r: BigInt,
    pub x: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TTriplets {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub T: Point<Bls12_381_1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2 {
    pub u1: BigInt,
    pub u2: BigInt,
}

#[derive(Debug)]
pub struct ProofError;

// based on https://eprint.iacr.org/2019/503.pdf figures 6 and 7
impl HSMCL {
    pub fn keygen(q: &BigInt, lam: &usize) -> Self {
        unsafe { pari_init(10000000, 2) };
        let mu = q.bit_length();
        assert!(lam > &(mu + 2));
        let k = lam - mu;
        let two = BigInt::from(2);
        let mut r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );

        let mut qtilde = next_probable_prime(&r);

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            r = BigInt::sample_range(
                &two.pow((k - 1) as u32),
                &(two.pow(k as u32) - BigInt::one()),
            );
            qtilde = next_probable_prime(&r);
        }

        assert!(BigInt::from(4) * q < qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -(&delta_k);
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        let mut r = BigInt::from(3);
        while jacobi(&delta_k, &r).unwrap() != 1 {
            r = next_probable_prime(&r)
        }

        let rgoth = BinaryQF::primeform(&delta_k, &r);

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(q).reduce();

        let gq = gq_tmp.exp(q);

        let x = BigInt::sample_below(&(&stilde * BigInt::from(2).pow(40)));
        let h = gq.exp(&x);

        let pk = PK {
            q: q.clone(),
            delta_k,
            delta_q,
            gq,
            h,
            stilde,
        };
        HSMCL { sk: x, pk }
    }

    pub fn keygen_with_setup(q: &BigInt, lam: &usize, seed: &BigInt) -> Self {
        unsafe { pari_init(100000000, 2) };
        let mu = q.bit_length();
        assert!(lam > &(mu + 2));
        let k = lam - mu;
        let two = BigInt::from(2);
        let mut r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );

        let mut qtilde = next_probable_prime(&r);

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            r = BigInt::sample_range(
                &two.pow((k - 1) as u32),
                &(two.pow(k as u32) - BigInt::one()),
            );
            qtilde = next_probable_prime(&r);
        }

        assert!(BigInt::from(4) * q < qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -(&delta_k);
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        // Assuming GRH the prime forms f_p with p<=6 ln^2(|delta_k|) generate the class group cf.
        // Cohen course comp. algebraic. number theory 5.5.1.
        // In practice we take only ln(-deltak)/ln(ln(-deltak))  primes and exponents up to 20 (cf. 5.5.2)
        // But as in https://eprint.iacr.org/2018/705.pdf page 20 we need pairwise coprime exponents
        // for the strong root assumption to hold so we take greater exponents to ensure that,
        // say up to 15 bits. (in fact for our purposes exponents globally coprime might be sufficient instead of pairwise coprimes)
        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let mut r = BigInt::from(3);
        let ln_delta_k = numerical_log(&(-&delta_k));

        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }
        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(q).reduce();

        let gq = gq_tmp.exp(q);

        let x = BigInt::sample_below(&(&stilde * BigInt::from(2).pow(40)));
        let h = gq.exp(&x);

        let pk = PK {
            q: q.clone(),
            delta_k,
            delta_q,
            gq,
            h,
            stilde,
        };
        HSMCL { sk: x, pk }
    }

    //repeat random element g_q generation using seed and delta_k
    pub fn setup_verify(pk: &PK, seed: &BigInt) -> Result<(), ErrorReason> {
        unsafe { pari_init(100000000, 2) };

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let ln_delta_k = numerical_log(&(-&pk.delta_k));
        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut r = BigInt::from(3);
        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&pk.delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&pk.delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }

        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&pk.delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(&pk.q).reduce();

        let gq = gq_tmp.exp(&pk.q);
        match gq == pk.gq {
            true => Ok(()),
            false => Err(ErrorReason::SetupError),
        }
    }

    pub fn encrypt(pk: &PK, m: &BigInt) -> Ciphertext {
        unsafe { pari_init(10000000, 2) };
        assert!(m < &pk.q);
        let r = BigInt::sample_below(&(&pk.stilde * BigInt::from(2).pow(40)));
        let exp_f = BinaryQF::expo_f(&pk.q, &pk.delta_q, m);
        let h_exp_r = pk.h.exp(&r);

        Ciphertext {
            c1: pk.gq.exp(&r),
            c2: h_exp_r.compose(&exp_f).reduce(),
            // c2: s,
        }
    }

    pub fn encrypt_predefined_randomness(pk: &PK, m: &BigInt, r: &BigInt) -> Ciphertext {
        unsafe { pari_init(10000000, 2) };
        assert!(m < &pk.q);
        let exp_f = BinaryQF::expo_f(&pk.q, &pk.delta_q, m);
        let h_exp_r = pk.h.exp(r);

        Ciphertext {
            c1: pk.gq.exp(r),
            c2: h_exp_r.compose(&exp_f).reduce(),
            // c2: s,
        }
    }

    pub fn decrypt(&self, c: &Ciphertext) -> BigInt {
        unsafe { pari_init(10000000, 2) };
        let c1_x = c.c1.exp(&self.sk);
        let c1_x_inv = c1_x.inverse();
        let tmp = c.c2.compose(&c1_x_inv).reduce();
        BinaryQF::discrete_log_f(&self.pk.q, &self.pk.delta_q, &tmp)
    }

    //TODO: add unit test
    pub fn eval_scal(c: &Ciphertext, val: &BigInt) -> Ciphertext {
        unsafe { pari_init(10000000, 2) };

        Ciphertext {
            c1: c.c1.exp(val),
            c2: c.c2.exp(val),
        }
    }

    //TODO: add unit test
    pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        unsafe { pari_init(10000000, 2) };

        Ciphertext {
            c1: c1.c1.compose(&c2.c1).reduce(),
            c2: c1.c2.compose(&c2.c2).reduce(),
        }
    }
}

pub fn next_probable_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    while !is_prime(&qtilde) {
        qtilde += &one;
    }
    qtilde
}

// used for testing small primes where our prime test fails. We use Pari isprime which provides
// determinstic perfect primality checking.
pub fn next_probable_small_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    let mut qtilde_gen = bn_to_gen(&(r + &one));
    unsafe {
        while isprime(qtilde_gen) as c_int != 1 {
            qtilde += &one;
            qtilde_gen = bn_to_gen(&qtilde);
        }
    }
    qtilde
}

// Automatically using q of the curve.
impl CLDLProof {
    pub fn prove(w: Witness, pk: PK, ciphertext: Ciphertext, q: Point<Bls12_381_1>) -> Self {
        unsafe { pari_init(10000000, 2) };
        let repeat = SECURITY_PARAMETER / C + 1;
        let triplets_and_fs_and_r_vec = (0..repeat)
            .map(|_| {
                let r1 = BigInt::sample_below(
                    &(&pk.stilde
                        * BigInt::from(2).pow(40)
                        * BigInt::from(2).pow(C as u32)
                        * BigInt::from(2).pow(40)),
                );
                let r2_fe = Scalar::<Bls12_381_1>::random();
                let r2 = r2_fe.to_bigint();
                let fr2 = BinaryQF::expo_f(&pk.q, &pk.delta_q, &r2);
                let pkr1 = pk.h.exp(&r1);
                let t2 = fr2.compose(&pkr1).reduce();
                let T = Point::<Bls12_381_1>::generator() * r2_fe;
                let t1 = pk.gq.exp(&r1);
                let fs = Sha256::new()
                    .chain(t1.to_bytes())
                    .chain(t2.to_bytes())
                    .chain_point(&T)
                    .result_bigint();
                (TTriplets { t1, t2, T }, fs, r1, r2)
            })
            .collect::<Vec<(TTriplets, BigInt, BigInt, BigInt)>>();
        let triplets_vec = (0..repeat)
            .map(|i| triplets_and_fs_and_r_vec[i].0.clone())
            .collect::<Vec<TTriplets>>();
        let fiat_shamir_vec = (0..repeat)
            .map(|i| &triplets_and_fs_and_r_vec[i].1)
            .collect::<Vec<&BigInt>>();
        let r1_vec = (0..repeat)
            .map(|i| triplets_and_fs_and_r_vec[i].2.clone())
            .collect::<Vec<BigInt>>();
        let r2_vec = (0..repeat)
            .map(|i| triplets_and_fs_and_r_vec[i].3.clone())
            .collect::<Vec<BigInt>>();
        // using Fiat Shamir transform
        let k = fiat_shamir_vec
            .iter()
            .fold(Sha256::new(), |hash, i| hash.chain_bigint(i))
            .result_bigint();

        let ten = BigInt::from(C as u32);
        let u1u2_vec = (0..repeat)
            .map(|i| {
                let k_slice_i = (&k >> (i * C)) & &ten;

                let u1 = &r1_vec[i] + &k_slice_i * &w.r;
                let u2 = BigInt::mod_add(
                    &r2_vec[i],
                    &(&k_slice_i * &w.x),
                    Scalar::<Bls12_381_1>::group_order(),
                );
                U1U2 { u1, u2 }
            })
            .collect::<Vec<U1U2>>();
        CLDLProof {
            pk,
            ciphertext,
            q,
            t_vec: triplets_vec,
            u_vec: u1u2_vec,
        }
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        unsafe { pari_init(10000000, 2) };
        // reconstruct k
        let repeat = SECURITY_PARAMETER / C + 1;
        let fs_vec = (0..repeat)
            .map(|i| {
                Sha256::new()
                    .chain(self.t_vec[i].t1.to_bytes())
                    .chain(self.t_vec[i].t2.to_bytes())
                    .chain_point(&self.t_vec[i].T)
                    .result_bigint()
            })
            .collect::<Vec<BigInt>>();
        let fs_t_vec = (0..repeat).map(|i| &fs_vec[i]).collect::<Vec<&BigInt>>();
        let mut flag = true;
        let k = fs_t_vec
            .iter()
            .fold(Sha256::new(), |hash, i| hash.chain_bigint(i))
            .result_bigint();
        let ten = BigInt::from(C as u32);

        let sample_size = &self.pk.stilde
            * (BigInt::from(2).pow(40))
            * BigInt::from(2).pow(C as u32)
            * (BigInt::from(2).pow(40) + BigInt::one());
        for i in 0..repeat {
            let k_slice_i = (&k >> (i * C)) & &ten;
            //length test u1:
            if self.u_vec[i].u1 > sample_size || self.u_vec[i].u1 < BigInt::zero() {
                flag = false;
            }
            // length test u2:
            if &self.u_vec[i].u2 > Scalar::<Bls12_381_1>::group_order()
                || self.u_vec[i].u2 < BigInt::zero()
            {
                flag = false;
            }
            let c1k = self.ciphertext.c1.exp(&k_slice_i);
            let t1c1k = self.t_vec[i].t1.compose(&c1k).reduce();
            let gqu1 = self.pk.gq.exp(&self.u_vec[i].u1);
            if t1c1k != gqu1 {
                flag = false;
            };

            let k_slice_i_bias_fe: Scalar<Bls12_381_1> =
                Scalar::<Bls12_381_1>::from(&(&k_slice_i + BigInt::one()));
            let g = Point::<Bls12_381_1>::generator();
            let t2kq = (&self.t_vec[i].T + &self.q * k_slice_i_bias_fe) - &self.q;
            let u2p = g * Scalar::<Bls12_381_1>::from(&self.u_vec[i].u2);
            if t2kq != u2p {
                flag = false;
            }

            let pku1 = self.pk.h.exp(&self.u_vec[i].u1);
            let fu2 = BinaryQF::expo_f(&self.pk.q, &self.pk.delta_q, &self.u_vec[i].u2);
            let c2k = self.ciphertext.c2.exp(&k_slice_i);
            let t2c2k = self.t_vec[i].t2.compose(&c2k).reduce();
            let pku1fu2 = pku1.compose(&fu2).reduce();
            if t2c2k != pku1fu2 {
                flag = false;
            }
        }
        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
    }
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support BigInt
// TODO: put in utility module, expend to Kronecker
pub fn jacobi(a: &BigInt, n: &BigInt) -> Option<i8> {
    let zero = BigInt::zero();
    // jacobi symbol is only defined for odd positive moduli
    if n.mod_floor(&BigInt::from(2)) == zero || n <= &BigInt::zero() {
        return None;
    }

    // Raise a mod n, then start the unsigned algorithm
    let mut acc = 1;
    let mut num = a.mod_floor(n);
    let mut den = n.clone();
    loop {
        // reduce numerator
        num = num.mod_floor(&den);
        if num == zero {
            return Some(0);
        }

        // extract factors of two from numerator
        while num.mod_floor(&BigInt::from(2)) == zero {
            acc *= two_over(&den);
            num = num.div_floor(&BigInt::from(2));
        }
        // if numerator is 1 => this sub-symbol is 1
        if num == BigInt::one() {
            return Some(acc);
        }
        // shared factors => one sub-symbol is zero
        if num.gcd(&den) > BigInt::one() {
            return Some(0);
        }
        // num and den are now odd co-prime, use reciprocity law:
        acc *= reciprocity(&num, &den);
        let tmp = num;
        num = den.clone();
        den = tmp;
    }
}

fn two_over(n: &BigInt) -> i8 {
    if n.mod_floor(&BigInt::from(8)) == BigInt::one()
        || n.mod_floor(&BigInt::from(8)) == BigInt::from(7)
    {
        1
    } else {
        -1
    }
}

fn reciprocity(num: &BigInt, den: &BigInt) -> i8 {
    if num.mod_floor(&BigInt::from(4)) == BigInt::from(3)
        && den.mod_floor(&BigInt::from(4)) == BigInt::from(3)
    {
        -1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_p256() {
        let q = BigInt::from_str_radix(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let ciphertext = HSMCL::encrypt(&hsmcl.pk, &m);
        let m_tag = hsmcl.decrypt(&ciphertext);

        assert_eq!(m, m_tag);
    }

    #[test]
    fn test_encryption_Bls12_381_1() {
        // Taken from https://safecurves.cr.yp.to/base.html
        let q = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let ciphertext = HSMCL::encrypt(&hsmcl.pk, &m);
        let m_tag = hsmcl.decrypt(&ciphertext);

        assert_eq!(m, m_tag);
    }

    #[test]
    fn test_encryption_mul_by_scalar_Bls12_381_1_lcm() {
        // Taken from https://safecurves.cr.yp.to/base.html
        let q: BigInt = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();

        let y_lcm_2_10 : BigInt =   BigInt::from_str_radix(
            "15161806181366890704755537519628428221282838501257142250824360639698299050776571382489681778825684381429314058890905101687022024744606800532531764952734582389201393752832486383043169059475949454418063248428056646723694341952991408637386677631205400831455008554143754794994126167401137152222379676492247471515691285702536834646805381995650206229354446213284302569283840180834930263739794772017863585682362821412785936104792844891075228278568320000",  
            10,
        ).unwrap();
        // let y_lcm_2_10 = (&q + BigInt::from(1)) * (&BigInt::from(2));
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let ciphertext = HSMCL::encrypt(&hsmcl.pk, &m);
        let c_y = HSMCL::eval_scal(&ciphertext, &y_lcm_2_10);
        let m_tag = hsmcl.decrypt(&c_y);
        let m_y = BigInt::mod_mul(&m, &y_lcm_2_10, &q);
        assert_eq!(m_y, m_tag);
    }

    #[test]
    fn test_zk_cl_dl() {
        // starts with hsm_cl encryption
        let q = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let r = BigInt::sample_below(&(&hsmcl.pk.stilde * BigInt::from(2).pow(40)));
        let ciphertext = HSMCL::encrypt_predefined_randomness(&hsmcl.pk, &m, &r);
        let witness = Witness { x: m.clone(), r };
        let m_fe = Scalar::<Bls12_381_1>::from(&m);
        let q = Point::<Bls12_381_1>::generator() * m_fe;
        let proof = CLDLProof::prove(witness, hsmcl.pk, ciphertext, q);
        assert!(proof.verify().is_ok())
    }

    #[test]
    #[should_panic]
    fn test_bad_q_zk_cl_dl() {
        // starts with hsm_cl encryption
        let q = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let r = BigInt::sample_below(&(&hsmcl.pk.stilde * BigInt::from(2).pow(40)));
        let ciphertext = HSMCL::encrypt_predefined_randomness(&hsmcl.pk, &m, &r);
        let witness = Witness { x: m.clone(), r };
        let m_fe: Scalar<Bls12_381_1> = Scalar::<Bls12_381_1>::from(&(&m + &BigInt::one()));
        let q = Point::<Bls12_381_1>::generator() * m_fe;
        let proof = CLDLProof::prove(witness, hsmcl.pk, ciphertext, q);
        assert!(proof.verify().is_ok())
    }

    #[test]
    #[should_panic]
    fn test_bad_witness_zk_cl_dl() {
        // starts with hsm_cl encryption
        let q = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(1000);
        let r = BigInt::sample_below(&(&hsmcl.pk.stilde * BigInt::from(2).pow(40)));
        let ciphertext = HSMCL::encrypt_predefined_randomness(&hsmcl.pk, &m, &r);
        let witness = Witness {
            x: &m + BigInt::one(),
            r,
        };
        let m_fe = Scalar::<Bls12_381_1>::from(&(&m + &BigInt::one()));
        let q = Point::<Bls12_381_1>::generator() * m_fe;
        let proof = CLDLProof::prove(witness, hsmcl.pk, ciphertext, q);
        assert!(proof.verify().is_ok())
    }

    #[test]
    fn test_log_dlog() {
        let q = BigInt::from_str_radix(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            10,
        )
        .unwrap();
        let hsmcl = HSMCL::keygen(&q, &1600);
        let m = BigInt::from(10000);
        let exp_f = BinaryQF::expo_f(&hsmcl.pk.q, &hsmcl.pk.delta_q, &m);
        let m_tag = BinaryQF::discrete_log_f(&hsmcl.pk.q, &hsmcl.pk.delta_q, &exp_f);
        assert_eq!(m, m_tag);
    }

    #[test]
    fn test_setup() {
        let q = BigInt::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        // digits of pi
        let seed = BigInt::from_str_radix(
                "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
            , 10).unwrap();

        let hsmcl = HSMCL::keygen_with_setup(&q, &1600, &seed);
        assert!(HSMCL::setup_verify(&hsmcl.pk, &seed).is_ok());
    }
}
