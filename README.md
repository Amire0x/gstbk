本项目结合了CL同态加密，GS-TBK方案，可验证秘密共享，零知识证明等技术实现的分布式群签名方案。
<a name="fwZry"></a>
## 背景
参考文章《基于代理的分布式身份管理方案》
<a name="jtili"></a>
## 项目结构
主要分为6个主要文件夹，分别为

- 3个角色模块 代理模块`proxy`, 管理员模块`node` 和 用户模块`user`
- 两个功能模块 CL同态加密模块 `class_group` 和 GSTBK部分功能和消息定义模块 `gs_tbk_scheme`

主要包含同态加密功能，消息定义，相关结构体定义，以及其他功能。<br />消息命名分为 发送方+接收方+消息阶段+发送类型<br />如 `NodeToProxyKeyGenPhaseFiveP2PMsg` 代表的是管理员P2P发送给代理的 KeyGen 第5阶段的消息。

- 以及测试模块` intergration_test`

主要演示了三个核心角色（1个 proxy， 4个node，4个user）之间的通信交互，从密钥生成到完成签名验证到公开的全过程。
<a name="YvbNh"></a>
## 部署
<a name="De4Pw"></a>
### 系统环境
系统为ubuntu，需要

- gcc，g++
- make
- rust 
- gmp:`sudo apt-get install libgmp-dev`
- pari-go:` sudo apt install pari-gp  `
- bison:`sudo apt install bison`
- clang:`sudo apt-get install -y libclang-dev`

最好再装个 vscode，对编辑比较友好
<a name="YK51O"></a>
### 编译
`cd`到项目根目录，进行`cargo build`，等待几分钟即可。<br />如果出现`class_group`文件夹的**权限不足**问题，编译的时候可能会出现权限不够的问题，使用`chmod -R u+x class_group`给文件夹及其里面所有内容赋予可执行权限即可

<a name="QXszq"></a>
## 功能接口说明
主要接口都分散到了各个角色的接口中，按需调用即可
<a name="YwfVq"></a>
### 联合公钥生成

- Proxy
```rust
pub fn keygen_phase_one(&mut self)->(ProxyKeyGenPhaseStartFlag, ProxyKeyGenPhaseOneBroadcastMsg)

pub fn keygen_phase_three(&self,msg_vec:Vec<NodeToProxyKeyGenPhaseTwoP2PMsg>) -> Result<HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg>,Error>

pub fn keygen_phase_five(&mut self,msg_vec:Vec<NodeToProxyKeyGenPhaseFiveP2PMsg>)->Result<ProxyToNodesKeyGenPhasefiveBroadcastMsg,Error>    
```

- Node
```rust
pub fn keygen_phase_one(&mut self, dkgtag:DKGTag,msg:ProxyKeyGenPhaseOneBroadcastMsg) -> NodeKeyGenPhaseOneBroadcastMsg

pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeKeyGenPhaseOneBroadcastMsg>)-> Result<NodeToProxyKeyGenPhaseTwoP2PMsg, Error>

pub fn keygen_phase_four(&mut self, msg:ProxyToNodeKeyGenPhaseThreeP2PMsg, )->Result<(), Error>

pub fn keygen_phase_five(&self) -> NodeToProxyKeyGenPhaseFiveP2PMsg
 
pub fn keygen_phase_six(&mut self,msg:ProxyToNodesKeyGenPhasefiveBroadcastMsg)
```
双方在收到对应消息的时候执行对应的函数即可。<br />第六阶段执行结束后即可拿到密钥碎片。
<a name="KdQPh"></a>
### 用户注册与密钥获取

- User
```rust
pub fn join_issue_phase_one(&self)->UserJoinIssuePhaseStartFlag

pub fn join_issue_phase_two(&mut self,msg:ProxyToUserJoinIssuePhaseOneP2PMsg)->UserToProxyJoinIssuePhaseTwoP2PMsg

pub fn join_issue_phase_three(&mut self,msg:ProxyToUserJoinIssuePhaseThreeP2PMsg)
```
User首先向代理发起请求。其余的按照收到对应消息的时候执行对应的函数即可。

- Proxy
```rust
pub fn join_issue_phase_one(&mut self)-> ProxyToUserJoinIssuePhaseOneP2PMsg

pub fn join_issue_phase_two(&mut self, msg:&UserToProxyJoinIssuePhaseTwoP2PMsg)->Result<(ProxyToNodesJoinIssuePhaseTwoBroadcastMsg), Error>

pub fn join_issue_phase_three(&mut self,msg_vec:Vec<NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg>)->(ProxyToUserJoinIssuePhaseThreeP2PMsg,ProxyToNodesJoinIssuePhaseThreeBroadcastMsg)

pub fn join_issue_phase_four(&self,msg_vec:Vec<NodeToProxyJoinIssuePhaseThreeP2PMsg>)->ProxyToNodesJoinIssuePhaseFourBroadcastMsg

pub fn join_issue_phase_five(&self,msg_vec:Vec<NodeToProxyJoinIssuePhaseFourP2PMsg>)->ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
```
按照收到对应消息的时候执行对应的函数即可。

- Node
```rust
pub fn join_issue_phase_two(&mut self, dkgtag:&DKGTag,msg:ProxyToNodesJoinIssuePhaseTwoBroadcastMsg)->Result<(),Error>

pub fn join_issue_phase_two_mta_one(&mut self, dkgtag:&DKGTag,msg:ProxyToNodesJoinIssuePhaseTwoBroadcastMsg) -> Result<NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg,Error>

pub fn join_issue_phase_two_mta_two(&mut self, dkgtag:&DKGTag, msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg)->NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg

pub fn join_issue_phase_two_mta_three(&mut self, dkgtag:&DKGTag, msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg)

pub fn join_issue_phase_two_final(&self,dkgtag:&DKGTag,msg:NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg) -> NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg

pub fn join_issue_phase_three(&mut self, msg:ProxyToNodesJoinIssuePhaseThreeBroadcastMsg) -> NodeToProxyJoinIssuePhaseThreeP2PMsg

pub fn join_issue_phase_five(&self, msg:ProxyToNodesJoinIssuePhaseFourBroadcastMsg)->NodeToProxyJoinIssuePhaseFourP2PMsg

pub fn join_issue_phase_six(&mut self, msg:ProxyToNodesJoinIssuePhaseFiveBroadcastMsg)   
```
按照收到对应消息的时候执行对应的函数即可。
<a name="JWhju"></a>
### 用户签名

- User
```rust
pub fn sign(&self,m:String) -> UserToProxySignPhaseP2PMsg
```

<a name="zto8U"></a>
### 用户撤销

- Proxy
```rust
pub fn revoke_phase_one(&mut self)->ProxyToNodesRevokePhaseOneBroadcastMsg

pub fn choose_revoke_user(&mut self,ru_list:Vec<u16>) -> RL

pub fn revoke_phase_two(&mut self,msg_vec:Vec<NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg>) -> (ProxyToNodesRevokePhaseTwoBroadcastMsg,ProxyToUserRevokePhaseBroadcastMsg)
```
按照收到对应消息的时候执行对应的函数即可。

- Node
```rust
pub fn revoke_phase_one_mta_one(&mut self,dkgtag:&DKGTag,msg:&ProxyToNodesRevokePhaseOneBroadcastMsg)->NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg

pub fn revoke_phase_one_mta_two(&mut self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg)->NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg

pub fn revoke_phase_one_mta_three(&mut self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg)

pub fn revoke_phase_one_final(&self,dkgtag:&DKGTag,msg:NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg)->NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg

pub fn revoke_phase_two(&mut self,msg:ProxyToNodesRevokePhaseTwoBroadcastMsg)
```
按照收到对应消息的时候执行对应的函数即可。
<a name="vVAuC"></a>
### 签名验证

- Proxy
```rust
pub fn verify_phase(&self,msg:&UserToProxySignPhaseP2PMsg,m:String)->ProxyToNodesVerifyPhaseBroadcastMsg
```
按照收到对应消息的时候执行对应的函数即可。

- Node
```rust
pub fn verify_phase(&self,msg:&ProxyToNodesVerifyPhaseBroadcastMsg,m:String)->Result<(),Error>
```
按照收到对应消息的时候执行对应的函数即可。	
<a name="ONuXC"></a>
### 用户揭示

- Proxy
```rust
pub fn open_phase_one(&self,msg:&UserToProxySignPhaseP2PMsg,msg_vec:Vec<NodeToProxyOpenPhaseOneP2PMsg>)->ProxyToNodesOpenPhaseOneBroadcastMsg

pub fn open_phase_two(&self,msg_vec:Vec<NodeToProxyOpenPhaseTwoP2PMsg>)->ProxyToNodesOpenPhaseTwoBroadcastMsg
```
按照收到对应消息的时候执行对应的函数即可。

- Node
```rust
pub fn open_phase_one(&self,msg:&ProxyToNodesVerifyPhaseBroadcastMsg)->NodeToProxyOpenPhaseOneP2PMsg

pub fn open_phase_two(&self,msg:&ProxyToNodesOpenPhaseOneBroadcastMsg)->NodeToProxyOpenPhaseTwoP2PMsg

pub fn open_phase_three(&self,msg:&ProxyToNodesOpenPhaseTwoBroadcastMsg)
```
按照收到对应消息的时候执行对应的函数即可。
<a name="BOvT2"></a>
## 测试
<a name="oyxd8"></a>
### 单主机测试版本信息配置
**注意**，此版本为单一主机下的测试配置，所有信息配置均在`intergration_test`文件夹下进行配置。<br />该文件夹下有 Proxy、Node1-4 和 User1-4 共9个角色信息，每个角色都需要进行配置。<br />配置是按照 **1** 个代理 Proxy，**4 **个管理员 Node，**4** 个用户 User 进行配置的。
<a name="Pplzk"></a>
#### 基本配置
**涉及到通信和门限的核心配置**

- `proxy/config/config_files/gs_tbk_config.json`文件中
   - 配置好代理的通信地址`proxy_addr`
   - 门限信息`threshold_params`其中`threshold`代表门限，即需要大于该值的数量的管理员才能恢复出密钥，`share_count`的值代表持有密钥碎片的管理员的数量

示例
```json
{
    "proxy_addr":"127.0.0.1:50000",
    "threshold_params":{
        "threshold":2,
        "share_counts":4
    }
}  
```

- `node/config/config_files/gs_tbk_config.json`文件中，
   - 配置好代理的通信地址，
   - 管理节点自身的通信地址`node_addr`
   - 以及门限信息

示例
```json
{
  "proxy_addr":"127.0.0.1:50000",
  "node_addr":"127.0.0.1:50001",
  "threshold_params":{
    "threshold":2,
    "share_count":4
  }
}
```

- `user/config/config_files/gs_tbk_config.json`文件中，
   - 配置好代理的通信地址，
   - 用户节点自身的通信地址`user_addr`

示例
```json
{
  "proxy_addr":"127.0.0.1:50000",
  "user_addr":"127.0.0.1:60001"
}
```


<a name="VTcAE"></a>
#### 日志配置
三种角色的都需要分别配置<br />在自己对应角色的文件夹下的`config/config_files/log4rs.yaml`文件中<br />以代理节点 Proxy 的配置为例<br />在`proxy/config/config_files/log4rs.yaml`文件中<br />重点配置日志存储路径`path`<br />示例
```yaml
refresh_rate: 30 seconds

appenders:
  file:
    kind: file
    path: "src/user/user4/logs/proxy.log"
    encoder:
      pattern: "{d} {l} {M} - {m}{n}"
    append: false

root:
  level: info
  appenders:
    - file
```

<a name="lnS3j"></a>
### 单主机测试版本运行
同样的所有执行都在`intergration_test`文件夹下，本次测试为从建立连接的 Setup Phase 一直到 最后的揭示 Open Phase，属于连贯性的测试，实际使用可以分开。<br />最终达到的演示效果为，

- 用户 1 签名验证不通过，签名无效显示已经被自然撤销，也就是密钥已过期。
- 用户 2、3 签名已经被手动撤销，签名无效。
- 用户 4 签名成功通过

随后将揭示用户1、2、3的身份。
<a name="czrEr"></a>
#### **用户密钥过期时间配置**
不同的主机执行的时长有所不同，故想达到上述效果需要配置合适的时间间隔。<br />配置路径在`gs_tbk_scheme/tree.rs`中的`set_time`函数中，修改`from_secs()`中数字即可。<br />本机配置为40G的DDR5内存+12700H的笔记本，测试设置的50。
<a name="WzePA"></a>
#### 建立连接

- 启动代理节点 Proxy，也就是运行`Proxy/proxy_node.rs`中的 `test`函数，开启后，Proxy 会开始监听并等待连接。
- 启动 **4** 个管理节点 Node，以 Node1 节点为例（以下都以该节点为例），也就是运行类似`Node1/node1.rs`里面的 `test` 函数，其余几个同理。
<a name="QGPlW"></a>
#### 密钥生成
无需操作。<br />Node 节点启动之后会自动和 Proxy 建立连接，并且调用 Keygen Phase 的函数，开始进行通信并生成密钥信息，最后的结果会存在对应`node1/info`下的 json 文件中。<br />控制台出现 `Keygen phase is finished！`就代表执行结束，可以开始执行下一阶段
<a name="LV2D6"></a>
#### 用户注册
以用户1为例，其他同理

- 启动 User 下的 `User1/user1.rs`中 `test` 函数，

启动后会自动与 Proxy 进行连接，然后开始发送注册信息，并在 Proxy 那儿完成验证和信息记录。
<a name="UhFFM"></a>
#### 用户密钥
无需操作。<br />完成记录后，Proxy 会向 Node 们提出用户密钥的申请，随后 Node 们会开始进行计算。<br />当 Proxy的控制台 输出`Join phase is finished!`代表该用户的密钥已经生成完毕<br />此时，方可开始第二个用户的注册与申请，重复 **用户注册**的步骤即可。
<a name="geMpl"></a>
#### 用户撤销
无需操作。<br />当 4 个用户都得到密钥之后，将开启撤销阶段，此时 Proxy 将选择第 2和第 3 个用户进行撤销，加入撤销名单。
<a name="f5Gbj"></a>
#### 用户签名
无需操作。<br />用户使用自己拿到的密钥对消息进行签名，调用 `sign` 函数即可。
<a name="hYoNX"></a>
#### 签名验证
无需操作。<br />Proxy 和 Node 都将对 User 的签名信息进行验证，不通过则进入揭示阶段。
<a name="sEGTH"></a>
#### 用户揭示
无需操作<br />Node 将对验证不通过的用户签名进行身份揭示。
<a name="dpVqd"></a>
## 日志阅读说明
以 node 的全过程完整日志为例
```yaml
2023-12-14T18:29:57.648425433+08:00 INFO intergration_test::node::node4::node4 - node1 is listening on 127.0.0.1:50004
2023-12-14T18:29:57.651676281+08:00 INFO node::gs_tbk_scheme::setup_phase - Setup phase is starting!
2023-12-14T18:29:58.655010946+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxySetupPhaseBroadcastMsg
2023-12-14T18:29:58.661655387+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxySetupPhaseFinishFlag
2023-12-14T18:29:58.661698508+08:00 INFO node::gs_tbk_scheme::setup_phase - Setup phase is finished!
2023-12-14T18:29:58.782874306+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseStartFlag
2023-12-14T18:29:58.868099585+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseOneBroadcastMsg
2023-12-14T18:29:58.868257264+08:00 INFO intergration_test::node::node4::node4 - Keygen phase is staring!
2023-12-14T18:29:58.904258382+08:00 INFO node::gs_tbk_scheme::keygen_phase - Key Gamma_A is generating!
2023-12-14T18:29:58.993300865+08:00 INFO node::gs_tbk_scheme::keygen_phase - Key Gamma_B is generating!
2023-12-14T18:29:59.067635279+08:00 INFO node::gs_tbk_scheme::keygen_phase - Key Gamma_O is generating!
2023-12-14T18:29:59.126046586+08:00 INFO node::gs_tbk_scheme::keygen_phase - Key Gamma_C is generating!
2023-12-14T18:29:59.132558664+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node ,Taget : Gamma_A Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.137507546+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node ,Taget : Gamma_B Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.141271804+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node ,Taget : Gamma_C Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.150685948+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node ,Taget : Gamma_O Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.163203536+08:00 INFO intergration_test::node::node4::node4 - From id : 3 ,Role : Group Manager Node ,Taget : Gamma_A Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.164658773+08:00 INFO intergration_test::node::node4::node4 - From id : 3 ,Role : Group Manager Node ,Taget : Gamma_B Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.173805155+08:00 INFO intergration_test::node::node4::node4 - From id : 3 ,Role : Group Manager Node ,Taget : Gamma_O Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.180917949+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node ,Taget : Gamma_C Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.181586054+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node ,Taget : Gamma_O Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.181717925+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node ,Taget : Gamma_B Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.188646750+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node ,Taget : Gamma_A Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:29:59.188748224+08:00 INFO intergration_test::node::node4::node4 - From id : 3 ,Role : Group Manager Node ,Taget : Gamma_C Get NodeKeyGenPhaseOneBroadcastMsg 
2023-12-14T18:30:07.055625484+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg
2023-12-14T18:30:07.132550695+08:00 INFO node::gs_tbk_scheme::keygen_phase - Gamma_B is generated!
2023-12-14T18:30:11.496372585+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg
2023-12-14T18:30:11.573195840+08:00 INFO node::gs_tbk_scheme::keygen_phase - Gamma_A is generated!
2023-12-14T18:30:15.978691952+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg
2023-12-14T18:30:16.058443553+08:00 INFO node::gs_tbk_scheme::keygen_phase - Gamma_O is generated!
2023-12-14T18:30:20.602796009+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg
2023-12-14T18:30:20.694527025+08:00 INFO node::gs_tbk_scheme::keygen_phase - Gamma_C is generated!
2023-12-14T18:30:22.493574581+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesKeyGenPhasefiveBroadcastMsg
2023-12-14T18:30:22.493730869+08:00 INFO intergration_test::node::node4::node4 - Keygen phase is finished!
2023-12-14T18:30:26.889202018+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
2023-12-14T18:30:27.395769457+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:30:27.406851303+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:30:32.420899547+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:30:34.373226927+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:30:36.834256111+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
2023-12-14T18:30:37.055261022+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFourBroadcastMsg
2023-12-14T18:30:37.299234961+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
2023-12-14T18:30:37.323703275+08:00 INFO node::gs_tbk_scheme::join_issue_phase - User 1's key is generated!
2023-12-14T18:30:42.529327330+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
2023-12-14T18:30:43.018515613+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:30:45.461829973+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:30:45.590806734+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:30:49.660967863+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:30:52.160853137+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
2023-12-14T18:30:52.359641570+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFourBroadcastMsg
2023-12-14T18:30:52.668313895+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
2023-12-14T18:30:52.745486173+08:00 INFO node::gs_tbk_scheme::join_issue_phase - User 2's key is generated!
2023-12-14T18:30:58.309905347+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
2023-12-14T18:30:58.893164887+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:30:58.938316283+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:31:03.773161255+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:31:03.775272535+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:31:08.148069925+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
2023-12-14T18:31:08.340183069+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFourBroadcastMsg
2023-12-14T18:31:08.601764450+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
2023-12-14T18:31:08.711445135+08:00 INFO node::gs_tbk_scheme::join_issue_phase - User 3's key is generated!
2023-12-14T18:31:14.682658450+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
2023-12-14T18:31:15.292343162+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:31:17.704520306+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
2023-12-14T18:31:17.877149867+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:31:21.966630797+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
2023-12-14T18:31:24.652069995+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
2023-12-14T18:31:24.863833363+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFourBroadcastMsg
2023-12-14T18:31:25.273293451+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesRevokePhaseOneBroadcastMsg
2023-12-14T18:31:25.422687857+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
2023-12-14T18:31:25.620611624+08:00 INFO node::gs_tbk_scheme::join_issue_phase - User 4's key is generated!
2023-12-14T18:31:25.622035386+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
2023-12-14T18:31:25.622555353+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
2023-12-14T18:31:28.324543676+08:00 INFO intergration_test::node::node4::node4 - From id : 2 ,Role : Group Manager Node  Get NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
2023-12-14T18:31:28.325339888+08:00 INFO intergration_test::node::node4::node4 - From id : 1 ,Role : Group Manager Node  Get NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
2023-12-14T18:31:30.115292906+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesRevokePhaseTwoBroadcastMsg
2023-12-14T18:31:32.217927708+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesVerifyPhaseBroadcastMsg
2023-12-14T18:31:33.314482194+08:00 INFO node::gs_tbk_scheme::verify_phase - User 4 Node::verify_phase() : verify successfully
2023-12-14T18:31:33.314638143+08:00 INFO intergration_test::node::node4::node4 - User : 4 has verified
2023-12-14T18:31:33.484730890+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesVerifyPhaseBroadcastMsg
2023-12-14T18:31:34.544424488+08:00 WARN node::gs_tbk_scheme::verify_phase - User 2 Node::verify_phase() : invalid signature
2023-12-14T18:31:34.544539654+08:00 INFO node::gs_tbk_scheme::open_phase - Open Phase is starting
2023-12-14T18:31:34.607174990+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesVerifyPhaseBroadcastMsg
2023-12-14T18:31:35.711496574+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesVerifyPhaseBroadcastMsg
2023-12-14T18:31:35.729543769+08:00 WARN node::gs_tbk_scheme::verify_phase - User 3 Node::verify_phase() : invalid signature
2023-12-14T18:31:35.729630049+08:00 INFO node::gs_tbk_scheme::open_phase - Open Phase is starting
2023-12-14T18:31:36.127646576+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseOneBroadcastMsg
2023-12-14T18:31:36.641917753+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseOneBroadcastMsg
2023-12-14T18:31:36.866919161+08:00 WARN node::gs_tbk_scheme::verify_phase - User 1 Proxy::verify_phase() : invalid hash
2023-12-14T18:31:36.867120767+08:00 INFO node::gs_tbk_scheme::open_phase - Open Phase is starting
2023-12-14T18:31:37.323385950+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseTwoBroadcastMsg
2023-12-14T18:31:37.355910265+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseTwoBroadcastMsg
2023-12-14T18:31:37.400600185+08:00 INFO node::gs_tbk_scheme::open_phase - Find the user successfully
2023-12-14T18:31:37.400709825+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.400740634+08:00 INFO node::gs_tbk_scheme::open_phase - This user 2 maybe used a revoked key or this user has been revoked in advance!
2023-12-14T18:31:37.400755976+08:00 INFO node::gs_tbk_scheme::open_phase - The infomation is: 
2023-12-14T18:31:37.400771259+08:00 INFO node::gs_tbk_scheme::open_phase - user_id:2
2023-12-14T18:31:37.400795548+08:00 INFO node::gs_tbk_scheme::open_phase - user address:"127.0.0.1:60002"
2023-12-14T18:31:37.400819325+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.400849742+08:00 INFO node::gs_tbk_scheme::open_phase - Open phase is finished!
2023-12-14T18:31:37.482530176+08:00 INFO node::gs_tbk_scheme::open_phase - Find the user successfully
2023-12-14T18:31:37.482641378+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.482662694+08:00 INFO node::gs_tbk_scheme::open_phase - This user 3 maybe used a revoked key or this user has been revoked in advance!
2023-12-14T18:31:37.482675987+08:00 INFO node::gs_tbk_scheme::open_phase - The infomation is: 
2023-12-14T18:31:37.482689175+08:00 INFO node::gs_tbk_scheme::open_phase - user_id:3
2023-12-14T18:31:37.482704305+08:00 INFO node::gs_tbk_scheme::open_phase - user address:"127.0.0.1:60003"
2023-12-14T18:31:37.482719138+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.482736077+08:00 INFO node::gs_tbk_scheme::open_phase - Open phase is finished!
2023-12-14T18:31:37.636166926+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseOneBroadcastMsg
2023-12-14T18:31:37.709004754+08:00 INFO intergration_test::node::node4::node4 - From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseTwoBroadcastMsg
2023-12-14T18:31:37.792880620+08:00 INFO node::gs_tbk_scheme::open_phase - Find the user successfully
2023-12-14T18:31:37.793042385+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.793068353+08:00 INFO node::gs_tbk_scheme::open_phase - This user 1 maybe used a invaild key!
2023-12-14T18:31:37.793081268+08:00 INFO node::gs_tbk_scheme::open_phase - The infomation is: 
2023-12-14T18:31:37.793093406+08:00 INFO node::gs_tbk_scheme::open_phase - user_id:1
2023-12-14T18:31:37.793110066+08:00 INFO node::gs_tbk_scheme::open_phase - user address:"127.0.0.1:60001"
2023-12-14T18:31:37.793126725+08:00 INFO node::gs_tbk_scheme::open_phase - ----------------------------------------------------------------------------------------
2023-12-14T18:31:37.793203662+08:00 INFO node::gs_tbk_scheme::open_phase - Open phase is finished!

```
`id = 0`，`Role = Proxy`代表收到来自 Proxy 的消息。<br />`Target：Gamma_A`代表收到的消息是属于 `Gamma_A` 密钥的。<br />消息结构如 `ProxyToNodesOpenPhaseTwoBroadcastMsg`代表的是 `Proxy`发送给 `Node` 的 `Open Phase Two` 阶段的广播信息。
<a name="zR3tI"></a>
## 
<a name="sN8JY"></a>
## 

