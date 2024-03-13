use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::node::Node;
use gs_tbk_scheme::params::{DKGTag};
use gs_tbk_scheme::messages::node::join_issue_msg::{MtAPhaseOneP2PMsg,MtAPhaseTwoP2PMsg};
use gs_tbk_scheme::messages::node::revoke_msg::{
    NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg,
    NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg,
    KiPishareInfo, 
    NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
};
use gs_tbk_scheme::messages::proxy::revoke_msg::{ProxyToNodesRevokePhaseOneBroadcastMsg,ProxyToNodesRevokePhaseTwoBroadcastMsg};

impl Node
{
    /// 启动mta的计算
    pub fn revoke_phase_one_mta_one(&mut self,dkgtag:&DKGTag,msg:&ProxyToNodesRevokePhaseOneBroadcastMsg)->NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
    {
        let mut mta_pone_p2pmsg_map:HashMap<usize, MtAPhaseOneP2PMsg> = HashMap::new();
        for tree_node in self.tree.as_ref().unwrap().cstbk(msg.leaf_node_id)
        {
            self.bbs_mtaparam_init(dkgtag, tree_node.id);
            let mta_pone_p2pmsg = self.mta_phase_one(dkgtag, tree_node.id);
            mta_pone_p2pmsg_map.insert(tree_node.id, mta_pone_p2pmsg);
        }
        NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
        {  
            sender:self.id.unwrap(),
            role:self.role.clone(),
            mta_pone_p2pmsg_map:mta_pone_p2pmsg_map
        }
    }

    pub fn revoke_phase_one_mta_two(&mut self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg)->NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
    {
        let mut mta_ptwo_p2pmsg_map:HashMap<usize, MtAPhaseTwoP2PMsg> = HashMap::new();
        for (tree_node_id, mta_pone_p2pmsg) in msg.mta_pone_p2pmsg_map
        {
            let mta_ptwo_p2pmsg = self.mta_phase_two(dkgtag, mta_pone_p2pmsg, tree_node_id);
            mta_ptwo_p2pmsg_map.insert(tree_node_id, mta_ptwo_p2pmsg);
        }
        NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            mta_ptwo_p2pmsg_map:mta_ptwo_p2pmsg_map 
        }
    }

    pub fn revoke_phase_one_mta_three(&mut self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg)
    {
        for (tree_node_id, mta_ptwo_p2pmsg) in msg.mta_ptwo_p2pmsg_map
        {
            self.mta_phase_three(dkgtag, mta_ptwo_p2pmsg, tree_node_id);
        }
    }

    /// 完成mta的联合计算，发送相关结果给代理
    pub fn revoke_phase_one_final(&self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg)->NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
    {
        let mut ki_pi_share_map:HashMap<usize, KiPishareInfo> = HashMap::new();
        for(tree_node_id, _) in msg.mta_ptwo_p2pmsg_map
        {
            let dkgparams = self.choose_dkgparam(dkgtag);
            let ki = dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().b.clone();
            let xi_j_i = dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().xi_j_i.clone();
            let pi_share = dkgparams.mtaparams_map.as_ref().unwrap().get(&tree_node_id).unwrap().pi_share.clone();
            ki_pi_share_map.insert(tree_node_id, KiPishareInfo { pi_share: pi_share, ki:ki, xi_j_i:xi_j_i});
        }
        NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            ki_pi_share_map:ki_pi_share_map,
        }
    }

    /// 存下撤销用户名单信息和revoke计算出来的信息
    pub fn revoke_phase_two(&mut self,msg:ProxyToNodesRevokePhaseTwoBroadcastMsg)
    {
        self.ei_info = Some(msg.ei_info);
        self.rl = Some(msg.rl);
    }    
}
