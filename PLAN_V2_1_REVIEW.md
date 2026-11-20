# 对《PLAN_V2_1_PATCH.md》的审计（审计之审计）

- **审计对象**：`PLAN_V2_1_PATCH.md`
- **交叉核对**：
  - `ARCHITECTURE_AND_PLAN.md` v2
  - `SECURITY_AUDIT.md`
  - Microsoft `SCardCancel` / Credential Provider 文档
  - Yubico PIV `GENERAL AUTHENTICATE` key-agreement 规范
  - RS-Key `production.md`、`threat-model.md`、`otp-fuses.md`、`piv.md`
- **总体结论**：**这是一份质量很高的补丁报告。** 它抓到了 v2 中真实存在的关键问题，尤其是 `lock-page58` / `pt.sh` / `firmware-strict-config` / `--protect`、改密顺序、PC/SC 阻塞、静态 `S_enroll`、attestation 固定等。  
  但它也有 **1 个会导致实现直接失败的 APDU 字节数错误**、**2 个严重度高估**、**1 个严重度低估**、以及 **2 个修复方案不完整**。不能原样合并；需要按下文修正后再升级为 v2.1。

---

## 1. 结论摘要

| 编号 | 报告结论 | 本次审计判定 | 建议严重度 |
| :--- | :--- | :--- | :---: |
| **VULN-01** | `password_last_set` 动态反推导致 100% 认证失败；P0 | **部分成立**：风险真实，但“100%”只在错误实现下成立；v2 代码的 AAD 已使用静态 vault 值。 | **P1** |
| **VULN-02** | AAD 无长度前缀导致碰撞；P0 | **部分成立**：文档写法有歧义；当前代码用 NUL 分隔，报告举的 `alice/pc1` 碰撞不成立。仍应升级为长度前缀。 | **P2** |
| **VULN-03** | PC/SC 无超时冻结 `LogonUI`；P0 | **成立，但修复不完整**：`SCardCancel` 不保证打断驱动层 `SCardConnect`/`SCardTransmit` 挂起；worker 线程可能泄漏。 | **P0（可用性）** |
| **VULN-04** | RS-Key provisioning 3 个盲区；P0 | **基本成立**：`lock-page58`、`pt.sh`、`strict-config`、`--protect` 均被官方文档证实；但 `strict-config` 是**可逆 DoS**，不是机密性破坏。 | **P0/P1** |
| **VULN-05** | 静态 `S_enroll` 的密码等价性；P0 | **成立**：无 post-compromise security；应写入威胁模型并支持轮换。补充：也不防 APDU **中继**。 | **P1** |
| **VULN-06** | 先改系统密码后打恢复单，崩溃永久锁死；P1 | **成立，且应升为 P0**。但补丁中“复用 Wrapped_DEK、无需再动卡”缺少 DEK 来源，需补。 | **P0（运维）** |
| **VULN-07** | `f9` attestation 自签名、OTP 烧录顺序；P1 | **成立**：`f9` CA 必须 pin；OTP 烧录应后置到 Phase 5。 | **P1** |
| **VULN-08** | 两次 VERIFY 的 retry 计数器；P1 | **成立**：第一次失败后绝不能第二次 VERIFY；需测试钉死。 | **P1** |
| **VULN-09** | 关闭 NLA 暴露 pre-auth 攻击面；P1 | **成立**：应升级为硬性网络前置条件；“绑定接口 IP”不是标准 RDP 设置，需用防火墙/VPN 实现。 | **P1** |
| **VULN-10** | PIV APDU 缺 `82 00`、精确报文未写；P2 | **发现正确，但补丁中的 APDU 长度错了 2 字节**；按报告字节发送会失败。 | **P1（正确性）** |
| **VULN-11** | ECDH 共享密钥/公钥合法性；P2 | **成立**：公钥必须 `from_sec1_bytes` 校验；共享密钥需非全零。 | **P2** |
| **VULN-12** | `SCardEndTransaction` 失败兜底；P2 | **成立**：需 `SELECT OpenPGP` + `SCARD_UNPOWER_CARD` 兜底。 | **P2** |
| **VULN-13** | Vault 反序列化 DoS / ACL；P2 | **成立**：输入上限、ACL、OOM 边界都要加。 | **P2** |

---

## 2. 最重要的问题：VULN-10 的 APDU 字节数错误

报告的发现是对的：**PIV ECDH 的 `GENERAL AUTHENTICATE` 必须在 `7C` 内先放空的响应标签 `82 00`，再放 `85 41 <65 字节未压缩 P-256 公钥>`。**  
Yubico 官方文档明确给出：

```text
7C len1 82 00 85 len2 <public key>
```

但报告给出的具体 APDU：

```text
00 87 11 9D 45 7C 43 82 00 85 41 <65-byte-pubkey> 00
```

**长度是错的**：

- 内层：`82 00` = 2 字节，`85 41 <65>` = 67 字节，合计 **69 字节 = 0x45**。
- 外层：`7C 45` + 69 字节 = **71 字节 = 0x47**。
- Lc 应该是 **0x47**，不是 0x45。
- `7C` 的长度应该是 **0x45**，不是 0x43。
- 整个 APDU 不含 Le 是 **76 字节**，不是报告写的 74 字节。

**正确报文**：

```text
00 87 11 9D 47
7C 45
  82 00
  85 41 <65-byte uncompressed P-256 public key: 04 || X || Y>
```

可选 Le：

```text
00 87 11 9D 47 7C 45 82 00 85 41 <65-byte-pubkey> 00
```

**正确响应**：

```text
7C 22 82 20 <32-byte shared secret> 90 00
```

如果按报告的 `45 / 43` 发送，卡会返回 `6700`（wrong length）或 `6A80`，ECDH 根本不会执行。报告在这点上“发现了正确的问题，但给了错误的修复字节”，这是不能原样合并的最重要原因。

> 当前 `scard-core/src/piv.rs` 里的实现只发了 `7C 43 85 41 ...`，也没有 `82 00`；这条必须修。正确的 `Lc`/`7C` 长度按上文。

---

## 3. VULN-01 / VULN-02：严重度高估，但不是无效

### 3.1 VULN-01（`password_last_set`）

报告说“每次登录动态反推 `password_last_set`，一旦进入 AAD 就会 100% 随机失败”。这个**风险本身成立**：

- `USER_INFO_3::usri3_password_age` 是**相对秒数**，`now - age` 会因两秒级截断出现 ±1 秒抖动；
- 如果把动态值放进 AAD，GCM 会失败；
- 如果严格相等比较，会误报“密码已更改”。

但报告把它定为 **P0 且“100% 概率”** 不准确：

- v2 的 `VaultBlob.password_last_set` 是注册时写入的静态值；`AAD_password` 应使用 **vault 中的静态值**；
- 当前 `KeyUnwrapped::decrypt_credential()` 已经使用 `self.vault.password_last_set`，不是登录时动态值；
- 所以“100% 失败”只在实现者把动态值拼进 AAD 时成立，是一个**实现陷阱**，不是当前设计的必然结果。

**建议**：

- 保持 AAD 使用 `vault.password_last_set`；
- 登录时只把动态 `current_last_set` 用于**变更检测**，并用 ±5 秒容差；
- 更优：如果可用，使用 `SamQueryInformationUser` 的绝对 `LastPasswordChange`，避免相对秒数；
- 严重度降为 **P1**，但补丁内容保留。

### 3.2 VULN-02（AAD 拼接）

报告举的例子：

```text
username="alice", computer="pc1"
username="alic",  computer="epc1"
```

只有在 AAD 完全无分隔符拼接时才会碰撞。当前代码的 `aad_password` 是：

```text
... || sid || 0x00 || username || 0x00 || computer || timestamp
```

`username` 和 `computer` 之间有 NUL 分隔，Windows 用户名/计算机名不能包含 NUL，所以报告举的具体碰撞**不成立**。但：

- 文档中的 AAD 写法确实没有写清分隔/长度；
- NUL 分隔依赖“字段永远不含 NUL”的非正式不变量；
- 用 `u32_le` 长度前缀更严谨、更可测试。

**建议**：采纳长度前缀编码，但严重度降为 **P2**，不要继续称为“P0 碰撞漏洞”。  
另外，报告建议 `username_lower` / `computer_name_upper`，必须保证注册与登录使用**同一个规范化函数**，否则会造成新的 AAD 不匹配。

---

## 4. VULN-03：问题成立，但 `SCardCancel` 不是万能钥匙

报告正确指出：`GetSerialization` 同步阻塞会冻结 `LogonUI`，用户可能无法切回原生密码框。这个问题是真实的，而且 v2 的“零线程”教条确实需要让步。

但报告给出的“worker 线程 + `SCardCancel(hContext)`”只解决一部分：

- Microsoft 文档说 `SCardCancel` 终止的是**特定 resource manager context 中等待外部动作的 outstanding actions**，特别适用于 `SCardGetStatusChange`；
- 它**不保证**能打断驱动层卡住的 `SCardConnect`、`SCardBeginTransaction` 或某些 `SCardTransmit`；
- 如果 worker 线程被驱动层永久卡住，`SCardCancel` 返回后线程仍然泄漏，下一次认证可能继续拿到“卡忙”；
- `TerminateThread` 是不安全的，不能在 `LogonUI` 里随便用。

**建议改为**：

1. 首选 **独立 helper 进程**：CP 的 `GetSerialization` 只负责通过命名管道把 SID/PIN 发给 helper，helper 以 SYSTEM 做 PC/SC + 解密；主线程 `WaitForSingleObject` 8 秒（Touch ALWAYS 时 18 秒）；超时直接 `TerminateProcess` helper，`LogonUI` 一定返回。helper 崩溃也不会拖垮 `LogonUI`。
2. 如果坚持 worker 线程：`SCardCancel` 只是 best-effort；必须在测试中用“阻塞 30 秒的代理读卡器”验证它真的能唤醒；如果唤醒不了，就不能承诺不冻结。
3. 超时值可配置；触摸提示要在阻塞前显示；超时后清理卡片 session（reset/unpower）。
4. 这会修改 v2 的“零后台线程”不变量：应改成“**除每请求一个带硬超时的隔离执行单元外，不做常驻后台轮询**”。

报告的方向正确，但“`SCardCancel` 强制打断正在阻塞的 PC/SC 调用”是过度承诺。

---

## 5. VULN-06：应升为 P0，但“无需再次动卡”缺少 DEK

报告发现的顺序问题非常关键，应该从 P1 升为 **P0**：

```text
生成随机密码 -> NetUserSetInfo 改系统密码 -> 打印恢复单 -> 写 Vault/自检
```

如果改密成功后打印机故障、GUI 崩溃、断电，用户没有恢复单，Vault 也没写入，确实可能被锁死。报告的“先自检、先核验恢复单、最后改系统密码”方向完全正确。

但补丁的第 4 步有一个未解决的依赖：

> 用新的 `password_last_set` 重新封装内层密码密文与 `AAD_password`（复用阶段 B 已验证的 `Wrapped_DEK`，无需再次动卡）。

`Wrapped_DEK` 只是“被 KEK 包装的 DEK”；要重新用新 AAD 加密 `P_new`，需要**明文 DEK**。得到明文 DEK 的方式只有：

- 阶段 B 自检时把 DEK 保留在 `Zeroizing<[u8;32]>` 中，跨用户确认/打印阶段一直持有，最后在阶段 D 使用并清零；或
- 阶段 D 重新用卡片做一次 ECDH（需要再次 VERIFY PIN，可能还要 Touch），拿到 DEK 后重新加密。

报告没有说明这一点，因此“无需再次动卡”只在“保留 DEK”时成立。建议补丁明确：

1. 阶段 B 自检后，将 DEK 保留在 `Zeroizing` 中（如果选择不保留，则阶段 D 必须重新动卡）；
2. 阶段 C 用户取消/核验失败时，立即清零 DEK 和 `P_new`，系统密码不变；
3. 阶段 D 改密成功后，用保留的 DEK + 新 `password_last_set` 重新加密 `P_new`；
4. 最终 Vault 写入成功后清零 DEK；
5. 如果 `NetUserSetInfo` 成功但 Vault 写入失败，恢复单是唯一救援；必须醒目告警；
6. `NetUserSetInfo` 对当前登录会话的影响、是否需要重新登录，要在 VM 中验证。

另外，报告说“恢复单严禁导出为本地 txt/pdf”是对的；但打印队列仍可能落盘，建议明确“只打印，不留文件”，并提醒打印机的 spool 风险。

---

## 6. VULN-04：官方文档支持，但严重度要拆开

报告引用的 RS-Key 官方文档证实了三点：

1. **`rsk otp burn` 之后必须 `rsk otp lock-page58`**；只 burn 不 lock，Page 58 仍可被 BOOTSEL 读取，flash dump 仍可能拿到 MKEK/DEVK。  
2. **`scripts/pt.sh` 必须在 `picotool seal --sign` 之前执行**；分区表在签名内，才能阻止 BOOTSEL `save/load` 回滚 store、重置 PIN 计数器（Token2 issue #37）。  
3. **默认 `firmware` 的 `WRITE CONFIG` 是 ungated**；`firmware-strict-config` 恢复 presence/PIN 门控并拒绝未授权 transport writes。  
4. **`--protect` 会把 Management Key 用 PIN 加密存到 `5FC109`**；知道 PIN 就获得 PIV 管理权限，确实不能用于 FamiliarSmartcard。

这些发现是报告最有价值的部分，v2 确实漏了它们。

但严重度要拆：

- `lock-page58` + `pt.sh`：**P0**（at-rest 保护和 PIN 计数器回滚）。
- `--protect`：**P0/P1**（PIN 泄露即管理权限；但 PIN 本身已经能解密 vault，管理权限会扩大为可删除/覆盖 9D 密钥）。
- `strict-config`：**P1（可用性）**。官方 threat model 说这是**可逆 DoS**，不是机密性/完整性破坏；任何 transport 都能重新启用。报告称“持久性 DoS”可以，但不要把它和 at-rest 密钥泄露并列成同一类 P0。
- 报告说“任意普通进程”可以 disable PIV；准确说法是“任何能访问 PC/SC 读卡器的进程”。在 Windows 上普通用户通常可以访问读卡器，所以风险成立。
- 建议补充：**`rsk backup export` 先做**；OTP burn 后设备 attestation key 会变，需要重新固定 `f9`；新部署应在 enroll 前 burn OTP，避免 pre-OTP 残留。

---

## 7. VULN-05：静态 `S_enroll` 成立，但还要补“中继”

报告正确指出：

- `FreshnessProven` 只能阻止“没有真实私钥的假卡/重放”；
- `S_enroll` 是静态的，一旦宿主/远程主机在某次成功登录时被攻陷并记录了它，攻击者可以离线解密 `VaultBlob`；
- 这不是 post-compromise security；需要文档化 + 重新绑定/轮换。

补充两点：

1. **中继攻击**：如果攻击者有一个能转发 APDU 的读卡器/中间人，并且真实卡片在附近，`FreshnessProven` 也会通过；它不是“防中继”。威胁模型应写清。
2. **宿主失陷时明文密码本来就会暴露**；`S_enroll` 的额外危害是“未来离线解密”，所以轮换是必要的。报告建议“轮换随机密码 + 重新生成 `eph_priv_enroll`/DEK”是正确的。
3. 如果要求 post-compromise security，需要重新设计（例如让 TPM 在验证卡片新鲜签名后才 unseal DEK，或使用卡片内 AES 直接解密密文）；当前 PIV ECDH + 主机解密架构做不到。

严重度：**P1 残余风险**，不是 P0 代码漏洞；但必须在威胁模型中诚实声明。

---

## 8. VULN-07：成立，`f9` 必须 pin

报告正确：

- RS-Key 的 `f9` attestation CA 是**设备首次上电自签**的 P-384 密钥，不是厂商统一根；
- 不 pin `f9` CA 的话，任何运行 RS-Key 的仿冒 RP2350 都能生成“合法”的 `f9` 自签名链；
- OTP burn 后设备 attestation 公钥会改变；应先开发/测试，Phase 5 再烧；
- 注册时应 `ATTEST (00 F9 00 9D)`，验证 9D 证明证书由当前卡 `f9` 签发，并检查 PIN policy `0x03`（ALWAYS）。

补充：

- `f9` attestation 证明的是“密钥在该设备内生成”，不是“设备是正品”；用户仍需核对设备序列号/指纹。
- 工厂重置或 OTP burn 后 `f9` CA 会变，必须重新 pin。
- 报告建议“Phase 0–4 用未烧录/测试板”；这与 RS-Key production 文档的“新部署先 burn 再 enroll”不矛盾：开发板不 burn，正式板在最终 enroll 前 burn。

---

## 9. VULN-08 / VULN-09：成立

### VULN-08

- 两次 VERIFY 的 retry 计数问题成立；
- 第一次 `VERIFY` 返回 `63 Cx` 时必须停止，绝不能第二次；
- 第二次失败（触控超时、传输错误）要给出不同错误文本；
- 建议测试断言：一次错误 PIN 只扣 1 次 retry。
- 报告说“第二次 VERIFY 因 USB 位翻转返回 63 C2”是推测，但测试价值成立。

### VULN-09

- 关闭 NLA 后任何能连 3389 的客户端都能触发 `LogonUI`，pre-auth 攻击面和连接槽位 DoS 成立；
- 报告要求“硬性前置条件”正确；
- 但“绑定在 WireGuard/Tailscale 接口 IP 上”不是标准 RDP listener 配置；应改为“Windows 防火墙只允许 VPN 接口/IPsec 认证流量到 3389”，或使用 RDP Gateway。
- 补充账户锁定、RDP 连接限制、审计日志；不要直接暴露公网。

---

## 10. VULN-11 / VULN-12 / VULN-13：成立

- **VULN-11**：`from_sec1_bytes` 校验公钥；共享密钥长度必须 32 且非全零。P-256 cofactor 为 1，全零实际很难出现，但检查成本低。  
- **VULN-12**：`SCardEndTransaction(SCARD_RESET_CARD)` 失败后，`SELECT OpenPGP AID` + `SCARD_UNPOWER_CARD` 兜底是合理的；但要测试读卡器是否支持 unpower，以及事务失败后 SELECT 是否还能发。  
- **VULN-13**：Vault 输入上限、ACL、OOM 边界都成立。当前代码 `MAX_TOTAL=8192`，建议收紧到 4096；DPAPI 之前先限制注册表读取长度；`catch_unwind` 不能捕获 OOM，必须防止超大分配。

---

## 11. 报告本身的结构性问题

1. **P0 数量虚高**：VULN-01/02 被列为 P0，但一个是条件性实现陷阱，一个是文档歧义；真正的 P0 是 VULN-03/04/06（以及 VULN-10 的正确性）。
2. **VULN-06 被低估**：它能把用户永久锁在系统外，应该比 `password_last_set` 抖动更优先。
3. **VULN-10 的字节数错误**：这是报告最严重的“审计错误”，因为实现者会照抄失败。
4. **VULN-03 的修复过度承诺**：`SCardCancel` 不是硬保证；需要 helper 进程或明确测试边界。
5. **VULN-06 的 DEK 依赖未说明**：`Wrapped_DEK` 不能直接重新加密密码；需要保留 DEK 或重新动卡。
6. **VULN-04 的 strict-config 严重度**：它是可逆 DoS，不是机密性破坏；应单列 P1。
7. **VULN-05 缺少中继攻击**：FreshnessProven 不防 relay；威胁模型要补。

---

## 12. 建议的合并顺序

1. 先修 **VULN-10** 的 APDU 字节数（否则 ECDH 不工作）。
2. 把 **VULN-06** 升为 P0，并补 DEK 生命周期。
3. 把 **VULN-03** 改为 helper 进程或“worker + 实测 SCardCancel + 明确不能保证”的方案。
4. 合并 **VULN-04** 的 provisioning 补丁，但拆开严重度。
5. 合并 **VULN-01/02** 的 AAD/时间戳修正，严重度降为 P1/P2。
6. 合并 **VULN-05/07/08/09/11/12/13**。
7. 最后再更新代码：`piv.rs` 的 `82 00`、`pcsc.rs` 的超时/兜底、`vault.rs` 的 AAD 长度前缀、`enroll` 的 `password_last_set` 容差、GUI 的两阶段改密。

---

## 13. 最终判定

- **报告的发现质量：高。** 尤其是 RS-Key provisioning、改密顺序、PC/SC 阻塞、静态 `S_enroll`、attestation pinning，都是 v2 的真实缺口。
- **报告的可执行性：中。** VULN-10 的字节数错误和 VULN-06 的 DEK 缺失会让实现者卡住或做错。
- **结论：不要原样合并。** 按本审计修正后，v2.1 会是一份很强的计划；当前代码也应暂停，先修 `piv.rs` 的 APDU 和 `pcsc.rs` 的超时策略，再继续。
