//use curv::BigInt;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use sha2::{Sha256, Digest};
use rand::seq::SliceRandom;
use log::{info,warn,error};
//use std::collections::HashMap;

use crate::user::User;
use gs_tbk_scheme::params::Sigma;
use gs_tbk_scheme::messages::user::sign_msg::UserToProxySignPhaseP2PMsg;
 
impl User
{
    /// 计算签名
    pub fn sign(&self,m:String) -> UserToProxySignPhaseP2PMsg
    {
        info!("Sign phase is starting!");
        println!("Sign phase is starting!");
        let gpk = &self.gpk.clone().unwrap();
        let ei_t_tree_nodes_id_vec = self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.keys().cloned().collect::<Vec<_>>();
        //println!("ei_t_tree_nodes_id_vec is {:?}",ei_t_tree_nodes_id_vec);
        let bbs_signatures_map_keys = self.gsk.as_ref().unwrap().bbs_signatures_map.keys().cloned().collect::<Vec<_>>();
        //println!("bbs_signatures_map keys is {:?} ", bbs_signatures_map_keys);
        let mut same_node_id:usize = 0;

        let fake_gsk_zeta_j = Scalar::<Bls12_381_1>::random();
        let fake_gsk_xi_j = Scalar::<Bls12_381_1>::random();

        // let fake_ei_zeta_j = Scalar::<Bls12_381_1>::random();
        // let fake_ei_xi_j = Scalar::<Bls12_381_1>::random();
        
        let rand_ei_id = ei_t_tree_nodes_id_vec.choose(&mut rand::thread_rng()).unwrap();
        for id in ei_t_tree_nodes_id_vec.clone()
        {
            if self.gsk.as_ref().unwrap().bbs_signatures_map.contains_key(&id) 
            && self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&id).unwrap().vj == self.gsk.as_ref().unwrap().bbs_signatures_map.get(&id).unwrap().uj
            {
                same_node_id = id;
                break;
            } 
        };
        //println!("The same id is {:?}",same_node_id);
        let A = if same_node_id == 0
        {
            Scalar::<Bls12_381_1>::random() * &self.gpk.as_ref().unwrap().g
        }
        else 
        {
            self.gsk.as_ref().unwrap().bbs_signatures_map.get(&same_node_id).unwrap().Aj.clone()
        };

        let Bt= if same_node_id == 0 
        {
            self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&rand_ei_id).as_ref().unwrap().Bj.clone()
        }
        else
        {
            self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&same_node_id).as_ref().unwrap().Bj.clone()
        };
    
        //println!("???????????????????");

        let alpha = Scalar::<Bls12_381_1>::random();
        let psi_1 = &alpha * &gpk.f;
        let psi_2 = &A + &alpha * gpk.g1.as_ref().unwrap();
        let psi_3 = &Bt + &alpha * &gpk.g2;

        let beta = Scalar::<Bls12_381_1>::random();
        let d = Scalar::<Bls12_381_1>::random();

        let delta_1 = if same_node_id == 0
        {
            &alpha * &fake_gsk_xi_j
        }
        else 
        {
            &alpha * &self.gsk.as_ref().unwrap().bbs_signatures_map.get(&same_node_id).as_ref().unwrap().xi_j
        };

        let delta_2 = if same_node_id == 0
        {
            &alpha * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&rand_ei_id).as_ref().unwrap().xi_j
        }
        else
        {
            &alpha * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&same_node_id).as_ref().unwrap().xi_j
        };

        let psi_4 = &beta * &self.ei_info.as_ref().unwrap().h_sim_t.clone();
        let psi_5 = &d * (self.usk.as_ref().unwrap() + &beta) * &gpk.g_sim;
        let psi_6=&d * &gpk.g_sim;
        let psi_7 = Scalar::<Bls12_381_2>::from_bigint(&d.to_bigint()) * &gpk.g_hat;

        let r_alpha= Scalar::<Bls12_381_1>::random();
        let r_beta= Scalar::<Bls12_381_1>::random();
        let r_zeta_1= Scalar::<Bls12_381_1>::random();
        let r_xi_1= Scalar::<Bls12_381_1>::random();
        let r_zeta_2= Scalar::<Bls12_381_1>::random();
        let r_xi_2= Scalar::<Bls12_381_1>::random();
        let r_u= Scalar::<Bls12_381_1>::random();
        let r_x= Scalar::<Bls12_381_1>::random();
        let r_delta_1= Scalar::<Bls12_381_1>::random();
        let r_delta_2= Scalar::<Bls12_381_1>::random();


        let R1 = Pair::compute_pairing(&(&r_zeta_1 * &gpk.h0), &gpk.g_hat)
                    .add_pair(&Pair::compute_pairing(&(&r_u * &gpk.h1), &gpk.g_hat))
                    .add_pair(&Pair::compute_pairing(&(&r_x * &gpk.h2), &gpk.g_hat))
                    .add_pair(&Pair::compute_pairing(&(&r_alpha * gpk.g1.as_ref().unwrap()), &gpk.vk_A.as_ref().unwrap()))
                    .add_pair(&Pair::compute_pairing(&(&r_delta_1 * gpk.g1.as_ref().unwrap()), &gpk.g_hat))
                    .add_pair(&Pair::compute_pairing(&(-&r_xi_1 * &psi_2), &gpk.g_hat));
        let R2 = Pair::compute_pairing(&(&r_zeta_2 * &gpk.h0), &gpk.g_hat)
                    .add_pair(&Pair::compute_pairing(&(&r_u * &gpk.h1), &gpk.g_hat))
                    .add_pair(&Pair::compute_pairing(&(&r_alpha * &gpk.g2), gpk.vk_B.as_ref().unwrap()))
                    .add_pair(&Pair::compute_pairing(&(&r_delta_2 * &gpk.g2), &gpk.g_hat))
                    .add_pair(&Pair::compute_pairing(&(&(-&r_xi_2) * &psi_3), &gpk.g_hat));
        
        let R3: Point<Bls12_381_1> = (&r_xi_1 * &psi_1) - &r_delta_1 * &gpk.f;
        let R4: Point<Bls12_381_1> = (&r_xi_2 * &psi_1) - &r_delta_2 * &gpk.f;
        let R5: Point<Bls12_381_1> = &r_beta * &self.ei_info.as_ref().unwrap().h_sim_t.clone();
        let R6: Point<Bls12_381_1> = (&r_x + &r_beta) * &psi_6;
        
        let c = Sha256::new()
        .chain_point(&psi_1)
        .chain_point(&psi_2)
        .chain_point(&psi_3)
        .chain_point(&psi_4)
        .chain_point(&psi_5)
        .chain_point(&psi_6)
        .chain_point(&psi_7)
        .chain_point(&R3)
        .chain_point(&R4)
        .chain_point(&R5)
        .chain_point(&R6)
        .chain(R1.e.to_string().as_bytes())
        .chain(R2.e.to_string().as_bytes())
        .chain(m.as_bytes())
        .result_scalar();


        let s_alpha: Scalar<Bls12_381_1> = &r_alpha + &c * &alpha;
        let s_beta: Scalar<Bls12_381_1> = &r_beta + &c * &beta;

        let s_zeta_1 = if same_node_id == 0
        {
            &r_zeta_1 + &c * &fake_gsk_zeta_j
        }
        else 
        {
            &r_zeta_1 + &c * &self.gsk.as_ref().unwrap().bbs_signatures_map.get(&same_node_id).as_ref().unwrap().zeta_j
        };

        let s_xi_1 = if same_node_id == 0
        {
            &r_xi_1 + &c*&fake_gsk_xi_j
        }
        else 
        {
            &r_xi_1 + &c * &self.gsk.as_ref().unwrap().bbs_signatures_map.get(&same_node_id).as_ref().unwrap().xi_j
        };

        let s_zeta_2: Scalar<Bls12_381_1> = if same_node_id == 0
        {
            &r_zeta_2 + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&rand_ei_id).as_ref().unwrap().zeta_j
        }
        else
        {
            &r_zeta_2 + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&same_node_id).as_ref().unwrap().zeta_j
        };

        let s_xi_2: Scalar<Bls12_381_1> = if same_node_id == 0
        {
            &r_xi_2 + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&rand_ei_id).as_ref().unwrap().xi_j
        }
        else
        {
            &r_xi_2 + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&same_node_id).as_ref().unwrap().xi_j
        };

        let s_u: Scalar<Bls12_381_1> = if same_node_id == 0
        {
            &r_u + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&rand_ei_id).as_ref().unwrap().vj
        }
        else
        {
            &r_u + &c * &self.ei_info.as_ref().unwrap().revoke_bbs_signatures_map.get(&same_node_id).as_ref().unwrap().vj
        };


        let s_x: Scalar<Bls12_381_1> = &r_x + &c * self.usk.as_ref().unwrap();
        let s_delta_1: Scalar<Bls12_381_1> = &r_delta_1 + &c * &delta_1;
        let s_delta_2: Scalar<Bls12_381_1> = &r_delta_2 + &c * &delta_2;

        let sigma = Sigma
        {
            psi_1,
            psi_2,
            psi_3,
            psi_4,
            psi_5,
            psi_6,
            psi_7,
            c,
            s_alpha,
            s_beta,
            s_zeta_1,
            s_xi_1,
            s_zeta_2,
            s_xi_2,
            s_u,
            s_x,
            s_delta_1, 
            s_delta_2,
        };
        info!("Sign phase is finished!");
        println!("Sign phase is finished!");
        //println!("{:?}",sigma);
        //println!("User {} Sign is finished",self.id.clone().unwrap());
        UserToProxySignPhaseP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            sigma
        } 
    }
}

#[test]
pub fn test()
{

}