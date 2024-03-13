use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use log::{info, warn};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::proxy::Proxy;
use crate::Error::{self, InvalidKey, InvalidSS};
use gs_tbk_scheme::messages::user::sign_msg::UserToProxySignPhaseP2PMsg;
use gs_tbk_scheme::messages::proxy::verify_msg::ProxyToNodesVerifyPhaseBroadcastMsg;

impl Proxy
{
    /// 验证用户的签名
    pub fn verify_phase(&self,msg:&UserToProxySignPhaseP2PMsg,m:String)->ProxyToNodesVerifyPhaseBroadcastMsg
    {   info!("Verify phase is staring!");
        let sigma = &msg.sigma;
        let gpk = self.gpk.clone().unwrap();
        if Pair::compute_pairing(&sigma.psi_6, &gpk.g_hat) != Pair::compute_pairing(&gpk.g_sim, &sigma.psi_7) {
            warn!("User {} Proxy::verify_phase() : invalid signature",msg.sender);
            warn!("This user has been revoked naturally or used an illegal signature.");
        }
        else 
        {
            let R1: Pair = Pair::compute_pairing(&(&sigma.s_zeta_1 * &gpk.h0), &gpk.g_hat)
                .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
                .add_pair(&Pair::compute_pairing(&(&sigma.s_x* &gpk.h2), &gpk.g_hat))
                .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * gpk.g1.as_ref().unwrap()), gpk.vk_A.as_ref().unwrap()))
                .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_1 * gpk.g1.as_ref().unwrap()), &gpk.g_hat))
                .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_1) * &sigma.psi_2), &gpk.g_hat))
                .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_2), gpk.vk_A.as_ref().unwrap()))
                .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat));
            let R2:Pair = Pair::compute_pairing(&(&sigma.s_zeta_2 * &gpk.h0), &gpk.g_hat)
                        .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
                        .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * &gpk.g2), gpk.vk_B.as_ref().unwrap()))
                        .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_2 * &gpk.g2), &gpk.g_hat))
                        .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_2) * &sigma.psi_3), &gpk.g_hat))
                        .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_3), gpk.vk_B.as_ref().unwrap()))
                        .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat))
                        .add_pair(&Pair::compute_pairing(&(&sigma.c * &self.ei_info.as_ref().unwrap().t.scalar * &gpk.h2), &gpk.g_hat));
            let R3: Point<Bls12_381_1> = (&sigma.s_xi_1 * &sigma.psi_1) - &sigma.s_delta_1 * &gpk.f;
            let R4: Point<Bls12_381_1> = (&sigma.s_xi_2 * &sigma.psi_1) - &sigma.s_delta_2 * &gpk.f;
            let R5: Point<Bls12_381_1> = (&sigma.s_beta * &self.ei_info.as_ref().unwrap().h_sim_t) + (-&sigma.c * &sigma.psi_4);
            let R6: Point<Bls12_381_1> = (&sigma.s_x + &sigma.s_beta) * &sigma.psi_6 + &(-&sigma.c * &sigma.psi_5);
            // println!("??????????????");
            // println!("User id {} psi_1 is {:?}",msg.sender,sigma.psi_1);
            let c = Sha256::new()
            .chain_point(&sigma.psi_1)
            .chain_point(&sigma.psi_2)
            .chain_point(&sigma.psi_3)
            .chain_point(&sigma.psi_4)
            .chain_point(&sigma.psi_5)
            .chain_point(&sigma.psi_6)
            .chain_point(&sigma.psi_7)
            .chain_point(&R3)
            .chain_point(&R4)
            .chain_point(&R5)
            .chain_point(&R6)
            .chain(R1.e.to_string().as_bytes())
            .chain(R2.e.to_string().as_bytes())
            .chain(m.as_bytes())
            .result_scalar();
            
            //println!("ID {:?} c is {:?}",msg.sender,c);
            //println!("??????????????"); 
            if c != sigma.c
            {
                warn!("User {} Proxy::verify_phase() : invalid hash",msg.sender);
                warn!("This user has been revoked naturally or used an illegal signature.");
            }
            else 
            {
                // Revocation check
                let grt_map = self.rl.as_ref().unwrap().grt_map.clone();
                if grt_map.contains_key(&msg.sender) && Pair::compute_pairing(&(grt_map.get(&msg.sender).unwrap() + &sigma.psi_4), &sigma.psi_7) == Pair::compute_pairing(&sigma.psi_5, &self.rl.as_ref().unwrap().h_hat_t)
                {
                    warn!("User {} Proxy::verify_phase() : invalid signature",msg.sender);
                    warn!("This user has been revoked in advance");
                }
                else 
                {
                    info!("User {} Proxy::verify_phase() : verify successfully",msg.sender);
                    
                }
            }   
        }
        info!("Verify phase is finished!");
        println!("Verify phase is finished!");
        ProxyToNodesVerifyPhaseBroadcastMsg
            {
                sender:self.id,
                role:self.role.clone(),
                user_id:msg.sender,
                sigma:msg.sigma.clone(),
                msg_user : msg.clone()
            }
    }
}