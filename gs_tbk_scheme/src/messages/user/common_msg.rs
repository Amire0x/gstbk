use serde::{Deserialize, Serialize};

use crate::messages::user::join_issue_msg::{UserJoinIssuePhaseStartFlag,UserToProxyJoinIssuePhaseTwoP2PMsg};
use crate::messages::user::revoke_msg::RevokePhaseStartFlag;
use crate::messages::user::sign_msg::UserToProxySignPhaseP2PMsg;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg 
{
    JoinIssueMsg(JoinIssueMsg),
    RevokeMsg(RevokeMsg),
    SignMsg(SignMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinIssueMsg 
{
    UserJoinIssuePhaseStartFlag(UserJoinIssuePhaseStartFlag),
    UserToProxyJoinIssuePhaseTwoP2PMsg(UserToProxyJoinIssuePhaseTwoP2PMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RevokeMsg
{
    RevokePhaseStartFlag(RevokePhaseStartFlag)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignMsg 
{
    UserToProxySignPhaseP2PMsg(UserToProxySignPhaseP2PMsg)
}

