use std::collections::HashMap;

use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use log::info;
use sha2::{Sha256, Digest};

use crate::node::{Node,MtaParams};
use crate::Error::{self, InvalidKey};
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::params::{DKGTag,Reg};
use gs_tbk_scheme::messages::proxy::join_issue_msg::{
    ProxyToNodesJoinIssuePhaseTwoBroadcastMsg, 
    ProxyToNodesJoinIssuePhaseThreeBroadcastMsg, 
    UserInfo,
    ProxyToNodesJoinIssuePhaseFourBroadcastMsg,
    ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
};
use gs_tbk_scheme::messages::node::join_issue_msg::{
    MtAPhaseOneP2PMsg,
    MtAPhaseTwoP2PMsg,
    NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg,
    NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg,
    CkiPishareInfo,
    NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg,
    NodeToProxyJoinIssuePhaseThreeP2PMsg,
    NodeToProxyJoinIssuePhaseFourP2PMsg
};
use gs_tbk_scheme::params::{hex_to_ciphertext,ciphertext_to_hex,cldl_proof_to_hex,hex_to_cldl_proof,pk_to_hex,hex_to_pk};

impl Node
{
    /// 初始化bbs签名的计算参数，主要是mta的参数
    pub fn bbs_mtaparam_init(&mut self, dkgtag:&DKGTag, tree_node_id:usize)
    {
        let k_i = Scalar::<Bls12_381_1>::random();
        let xi_j_i = Scalar::<Bls12_381_1>::random();
        self.get_addshare(dkgtag);
        let gamma_i = self.choose_dkgparam(&dkgtag).addshare.as_ref().unwrap().clone();

        let dkgparam = self.choose_dkgparam(dkgtag);
        let mut mtaparams_map:HashMap<usize,MtaParams> = match dkgparam.mtaparams_map.clone(){
            None =>{
                HashMap::new()
            }
            Some(mtaparam_map)=>{
                dkgparam.mtaparams_map.clone().unwrap()
            }
        };
        
        let mtaparams = MtaParams
        {
            a: &gamma_i+ &xi_j_i,
            b:k_i.clone(),
            xi_j_i:xi_j_i.clone(),
            pi_share:(&gamma_i+&xi_j_i) * &k_i
        };
        mtaparams_map.insert(tree_node_id, mtaparams);
        match dkgtag 
        {
            DKGTag::Gamma_A=>
            {
                self.dkgparams.dkgparam_A.as_mut().unwrap().mtaparams_map = Some(mtaparams_map);
            }
            DKGTag::Gamma_B=>
            {
                self.dkgparams.dkgparam_B.as_mut().unwrap().mtaparams_map = Some(mtaparams_map);
            }
            DKGTag::Gamma_O=>
            {
                self.dkgparams.dkgparam_O.as_mut().unwrap().mtaparams_map = Some(mtaparams_map);
            },
            DKGTag::Gamma_C=>
            {
                self.dkgparams.dkgparam_C.as_mut().unwrap().mtaparams_map = Some(mtaparams_map);
            }
        }
    }

    pub fn mta_phase_one(&mut self,dkgtag:&DKGTag,tree_node_id:usize)-> MtAPhaseOneP2PMsg
    {
        let dkgparam = self.choose_dkgparam(&dkgtag);
        let group = &self.group;
        let alice_pk = self.clkeys.pk.clone();
        
        let a = dkgparam.mtaparams_map.as_ref().unwrap().get(&tree_node_id).as_ref().unwrap().a.clone();
        let (c_a, _) = encrypt(&group, &alice_pk, &a);
        let c_a_hex = ciphertext_to_hex(&c_a);
        MtAPhaseOneP2PMsg
        {
            sender:self.id.unwrap(),
            c_a_hex:c_a_hex,
            alice_pk_hex:pk_to_hex(&alice_pk)
        }
    }

    pub fn mta_phase_two(&mut self,dkgtag:&DKGTag,mta_pone_p2pmsg:MtAPhaseOneP2PMsg,tree_node_id:usize)->MtAPhaseTwoP2PMsg
    {
        let group = &self.group;
        let b = self.choose_dkgparam(&dkgtag).mtaparams_map.as_ref().unwrap().get(&tree_node_id).as_ref().unwrap().b.clone();
        let pi_share = self.choose_dkgparam(&dkgtag).mtaparams_map.as_ref().unwrap().get(&tree_node_id).as_ref().unwrap().pi_share.clone();
        let alice_pk = hex_to_pk(&mta_pone_p2pmsg.alice_pk_hex);
        let bob_pk = self.clkeys.pk.clone();

        let g = Point::<Bls12_381_1>::generator();
        let g_b = g * &b;
        let r = Scalar::<Bls12_381_1>::random();
        let (c_r,_) = encrypt(&group, &alice_pk, &r);
        let beta = -&r;
        match dkgtag  
        {
            DKGTag::Gamma_A=>
            {
                self.dkgparams.dkgparam_A.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &beta;
            }
            DKGTag::Gamma_B=>
            {
                self.dkgparams.dkgparam_B.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &beta;
            }
            DKGTag::Gamma_O=>
            {
                self.dkgparams.dkgparam_O.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &beta;
            }
            DKGTag::Gamma_C=>
            {
                self.dkgparams.dkgparam_C.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &beta;
            }
        }
        let g_beta = g * &beta;
        let c_a = hex_to_ciphertext(&mta_pone_p2pmsg.c_a_hex);

        let c_alpha = eval_sum(&eval_scal(&c_a,&b.to_bigint()),&c_r);
        let (c_b, b_proof) = verifiably_encrypt(&group, &bob_pk, (&b, &g_b));
        let (c_beta,beta_proof) = verifiably_encrypt(&group,&bob_pk,(&beta,&g_beta));

        MtAPhaseTwoP2PMsg
        {
            sender:self.id.unwrap(),
            c_alpha_hex:ciphertext_to_hex(&c_alpha),
            c_b_hex:ciphertext_to_hex(&c_b),
            g_b:g_b,
            b_proof_hex:cldl_proof_to_hex(&b_proof),
            c_beta_hex:ciphertext_to_hex(&c_beta),
            g_beta,
            beta_proof_hex:cldl_proof_to_hex(&beta_proof),
            bob_pk_hex:pk_to_hex(&bob_pk)
        } 
    }

    pub fn mta_phase_three(&mut self, dkgtag:&DKGTag, mta_ptwo_p2pmsg:MtAPhaseTwoP2PMsg,tree_node_id:usize)
    {
        let group = &self.group;
        let pi_share = self.choose_dkgparam(&dkgtag).mtaparams_map.as_ref().unwrap().get(&tree_node_id).as_ref().unwrap().pi_share.clone();
        let alice_sk = &self.clkeys.sk;
        let bob_pk = hex_to_pk(&mta_ptwo_p2pmsg.bob_pk_hex);
        let a = self.choose_dkgparam(&dkgtag).mtaparams_map.as_ref().unwrap().get(&tree_node_id).as_ref().unwrap().a.clone();

        let c_alpha = hex_to_ciphertext(&mta_ptwo_p2pmsg.c_alpha_hex);
        let alpha = decrypt(&group,&alice_sk,&c_alpha);

        let g = Point::<Bls12_381_1>::generator();
        let g_alpha = g * &alpha;
        let alpha_tag = &a * &mta_ptwo_p2pmsg.g_b-&mta_ptwo_p2pmsg.g_beta;

        let b_proof = hex_to_cldl_proof(&mta_ptwo_p2pmsg.b_proof_hex);
        let beta_proof = hex_to_cldl_proof(&mta_ptwo_p2pmsg.beta_proof_hex);

        let c_b = hex_to_ciphertext(&mta_ptwo_p2pmsg.c_b_hex);
        let c_beta = hex_to_ciphertext(&mta_ptwo_p2pmsg.c_beta_hex); 
        if b_proof.verify(&group,&bob_pk,&c_b, &mta_ptwo_p2pmsg.g_b ).is_ok()
            &&beta_proof.verify(&group,&bob_pk,&c_beta, &mta_ptwo_p2pmsg.g_beta ).is_ok()
            &&g_alpha==alpha_tag
        {
            //y验证成功后，累加自己的alpha到自己的pi share上面
        match dkgtag 
        {
            DKGTag::Gamma_A=>
            {
                self.dkgparams.dkgparam_A.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &alpha;
            }
            DKGTag::Gamma_B=>
            {
                self.dkgparams.dkgparam_B.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &alpha;
            }
            DKGTag::Gamma_O=>
            {
                self.dkgparams.dkgparam_O.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &alpha;
            }
            DKGTag::Gamma_C=>
            {
                self.dkgparams.dkgparam_O.as_mut().unwrap().mtaparams_map.as_mut().unwrap().get_mut(&tree_node_id).as_mut().unwrap().pi_share = pi_share + &alpha;
            }
        }
            
        }
        else
        {
            println!("MTA Error");
        }

    }

    /// 非参与方，验证用户的proof， 然后存储下相关的用户信息
    pub fn join_issue_phase_two(&mut self, dkgtag:&DKGTag,msg:ProxyToNodesJoinIssuePhaseTwoBroadcastMsg)->Result<(),Error>
    {
        info!("User {} is joining!",msg.user_id);
        println!("User {} is joining!",msg.user_id);
        let gpk = self.gpk.as_ref().unwrap();
        let R = (&gpk.h2*&msg.s_x)-(&msg.X * &msg.c_x);
        let R_sim = (&gpk.g_sim * &msg.s_x)-(&msg.X_sim * &msg.c_x);
        let vc_x_b=Sha256::new()
            .chain_point(&msg.X)
            .chain_point(&msg.X_sim)
            .chain_point(&R)
            .chain_point(&R_sim)
            .result_bigint();
        let vc_x = Scalar::<Bls12_381_1>::from_bigint(&vc_x_b);
        assert_eq!(&msg.c_x,&vc_x);
        if &msg.c_x==&vc_x
        {
            let mut user_info_map:HashMap<u16,UserInfo> = match self.user_info_map.clone(){
                None =>{
                    HashMap::new()
                }
                Some(user_info)=>{
                    self.user_info_map.clone().unwrap()
                }
            };
            user_info_map.insert(msg.user_id.clone(), msg.user_info.clone());
            self.user_info_map = Some(user_info_map);
            Ok(())
        }
        else 
        {
            Err(Error::InvalidZkp)
        }
    }

    /// 参与方，验证用户的proof，然后初始化bbs签名的参数，开始进行批量mta计算
    pub fn join_issue_phase_two_mta_one(&mut self, dkgtag:&DKGTag,msg:ProxyToNodesJoinIssuePhaseTwoBroadcastMsg) -> Result<NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg,Error>
    {
        let gpk = self.gpk.as_ref().unwrap();
        let R = (&gpk.h2*&msg.s_x)-(&msg.X * &msg.c_x);
        let R_sim = (&gpk.g_sim * &msg.s_x)-(&msg.X_sim * &msg.c_x);
        let vc_x_b=Sha256::new()
            .chain_point(&msg.X)
            .chain_point(&msg.X_sim)
            .chain_point(&R)
            .chain_point(&R_sim)
            .result_bigint();
        let vc_x = Scalar::<Bls12_381_1>::from_bigint(&vc_x_b);
        assert_eq!(&msg.c_x,&vc_x);
        if &msg.c_x==&vc_x
        {
            let mut user_info_map:HashMap<u16,UserInfo> = match self.user_info_map.clone(){
                None =>{
                    HashMap::new()
                }
                Some(user_info)=>{
                    self.user_info_map.clone().unwrap()
                }
            };
            user_info_map.insert(msg.user_id.clone(), msg.user_info.clone());
            self.user_info_map = Some(user_info_map);

            let mut mta_pone_p2pmsg_map:HashMap<usize, MtAPhaseOneP2PMsg> = HashMap::new();

            // Initialize bbs param for every tree node and send mta phase one msg
            for tree_node in self.tree.as_ref().unwrap().path(msg.user_info.leaf_node.id.clone())
            {
                self.bbs_mtaparam_init(dkgtag, tree_node.id);
                let mta_pone_p2pmsg = self.mta_phase_one(dkgtag, tree_node.id);
                mta_pone_p2pmsg_map.insert(tree_node.id, mta_pone_p2pmsg);
            }
            Ok
            (
                NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
                {
                    sender:self.id.unwrap(),
                    role:self.role.clone(),
                    user_id:msg.user_id,
                    mta_pone_p2pmsg_map:mta_pone_p2pmsg_map
                }
            )
        }
        else 
        {
            Err(InvalidKey)
        }
 
        
        
    } 

    pub fn join_issue_phase_two_mta_two(&mut self, dkgtag:&DKGTag, msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg)->NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
    {
        
        let mut mta_ptwo_p2pmsg_map:HashMap<usize, MtAPhaseTwoP2PMsg> = HashMap::new();
        for (tree_node_id, mta_pone_p2pmsg) in msg.mta_pone_p2pmsg_map
        {
            let mta_ptwo_p2pmsg = self.mta_phase_two(dkgtag, mta_pone_p2pmsg, tree_node_id);
            mta_ptwo_p2pmsg_map.insert(tree_node_id, mta_ptwo_p2pmsg);
        }
        NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
        {
            sender:self.id.unwrap(), 
            role:self.role.clone(), 
            user_id:msg.user_id,
            mta_ptwo_p2pmsg_map:mta_ptwo_p2pmsg_map 
        }
    }

    pub fn join_issue_phase_two_mta_three(&mut self, dkgtag:&DKGTag, msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg)
    {
        for (tree_node_id, mta_ptwo_p2pmsg) in msg.mta_ptwo_p2pmsg_map.clone()
        {
            self.mta_phase_three(dkgtag, mta_ptwo_p2pmsg, tree_node_id);
        }
    }

    /// mta计算结束之后，加密参数和mta结果，然后发送给代理
    pub fn join_issue_phase_two_final(&self,dkgtag:&DKGTag,msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg) -> NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg
    {
        let mut c_ki_pi_share_map:HashMap<usize, CkiPishareInfo> = HashMap::new();
        for(tree_node_id, _) in msg.mta_ptwo_p2pmsg_map
        {
            let dkgparams = self.choose_dkgparam(dkgtag);
            let (c_ki,_) = encrypt(&self.group, &hex_to_pk(&self.user_info_map.as_ref().unwrap().get(&(msg.user_id)).unwrap().pk_hex), &dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().b);
            let pi_share = dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().pi_share.clone();
            let c_ki_hex = ciphertext_to_hex(&c_ki);
            c_ki_pi_share_map.insert(tree_node_id, CkiPishareInfo {pi_share: pi_share, c_ki_hex: c_ki_hex, xi_j_i:dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().xi_j_i.clone()});
        }
        NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            user_id:msg.user_id,
            c_ki_pi_share_map:c_ki_pi_share_map,
        }
    }

    /// 计算 A_gamma_c_i_k
    pub fn join_issue_phase_three(&mut self, msg:ProxyToNodesJoinIssuePhaseThreeBroadcastMsg) -> NodeToProxyJoinIssuePhaseThreeP2PMsg
    {
        self.get_addshare(&DKGTag::Gamma_C);
        let mut A_gamma_C_i_k_map:HashMap<usize, Point<Bls12_381_1>>=HashMap::new();
        for (tree_node_id,A_1_k) in msg.A_1_k_map 
        {
            let A_gamma_C_i_k = &A_1_k * self.dkgparams.dkgparam_C.as_ref().unwrap().addshare.as_ref().unwrap();
            A_gamma_C_i_k_map.insert(tree_node_id, A_gamma_C_i_k);
        }

        NodeToProxyJoinIssuePhaseThreeP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            user_id:msg.user_id,
            A_gamma_C_i_k_map:A_gamma_C_i_k_map
        }
    }

    /// 计算 A_gamma_C_ki
    pub fn join_issue_phase_five(&self, msg:ProxyToNodesJoinIssuePhaseFourBroadcastMsg)->NodeToProxyJoinIssuePhaseFourP2PMsg
    {
        let mut A_gamma_C_k_ki_map:HashMap<usize, Point<Bls12_381_1>>=HashMap::new();
        for (tree_node_id,A_gamma_C_k) in msg.A_gamma_C_k_map
        {
            let A_gamma_C_k_ki = &A_gamma_C_k * &self.dkgparams.dkgparam_A.as_ref().unwrap().mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().b;
            A_gamma_C_k_ki_map.insert(tree_node_id, A_gamma_C_k_ki);
        }

        NodeToProxyJoinIssuePhaseFourP2PMsg
         {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            user_id:msg.user_id,
            A_gamma_C_k_ki_map:A_gamma_C_k_ki_map,
         }
    }

    /// 获取用户的加密签名结果，存储在reg中
    pub fn join_issue_phase_six(&mut self, msg:ProxyToNodesJoinIssuePhaseFiveBroadcastMsg)
    {
        let user_info = self.user_info_map.as_mut().unwrap().get(&msg.user_id).unwrap().clone();
        let regi = Reg{
            tau_i:user_info.tau,
            grt_i:user_info.X_sim,
            Aj_gamma_C_map:msg.A_gamma_C_map,
        };
        let mut reg:HashMap<u16,Reg> = match self.reg.clone(){
            None =>{
                HashMap::new()
            }
            Some(regi)=>{
                self.reg.clone().unwrap()
            }
        };
        reg.insert(msg.user_id, regi);
        self.reg = Some(reg);
        info!("User {}'s key is generated!",msg.user_id);
        println!("User {}'s key is generated!",msg.user_id)
    }

}
