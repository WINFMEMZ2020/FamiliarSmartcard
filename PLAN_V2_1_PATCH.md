# FamiliarSmartcard 架构计划 v2 深度漏洞审查与 v2.1 待合并补丁说明

- **审查对象**：`ARCHITECTURE_AND_PLAN.md` (v2, 2026-11-21)
- **交叉核对依据**：
  - `SECURITY_AUDIT.md` (v1 审计报告)
  - RS-Key 官方文档：`docs/guides/piv.md`、`docs/limitations.md`、`docs/threat-model.md`、`docs/otp-fuses.md`、`docs/production.md`
  - Windows Credential Provider V2 / Winlogon / LSA / PC/SC 官方规范
- **文件用途**：本文件列出 v2 计划中**新确认的深层漏洞与工程缺陷**，并在第二部分提供**可直接合并入 `ARCHITECTURE_AND_PLAN.md`（升级为 v2.1）的结构化补丁文本**。

---

## 第一部分：新确认的深层漏洞与风险清单

### 1. 阻断级 / 架构级漏洞（P0 / Blocker）

#### [VULN-01] `password_last_set` 动态反推导致 100% 概率的随机认证失败（可用性阻断）
- **位置**：v2 第 3.2 节第 5 条、第 4.1 节、第 4.3 节第 2 步
- **机理**：
  - v2 计划规定：`password_last_set`“由 `NetUserGetInfo` 的 `usri3_password_age` 推算”，并且将其放入 `AAD_password` 参与 AES-256-GCM 认证。
  - Windows `USER_INFO_3::usri3_password_age` 返回的是**密码自上次修改以来的秒数（相对秒数）**，不是绝对时间戳！
  - 如果用 `CurrentTime - usri3_password_age` 反推绝对时间戳，由于两次调用之间的秒级截断边界（例如 `now` 跨秒但 `age` 未跨秒，或系统 NTP 校时微调），每次登录算出的 `password_last_set` 都会出现 **±1～2 秒的抖动**。
  - 一旦该抖动值进入 `AAD_password` 或用于严格相等比较 (`==`)，会导致 **AES-256-GCM Tag 校验直接失败** 或误报“密码已更改”！
- **修复方案**：
  1. **AAD 必须使用静态存储值**：`AAD_password` 中绑定的必须是 `VaultBlob.password_last_set`（注册时写入的静态 `u64` 值），绝不能用登录时动态反推的值拼装 AAD。
  2. **密码变更检测采用容差窗口或 LSA 绝对时间戳**：
     - 方案 A（推荐）：使用 `SamQueryInformationUser` / `NetUserGetInfo` + 当前 `GetSystemTimeAsFileTime` 反推 Unix 秒数时，比对条件设为 `(computed_last_set.abs_diff(vault.password_last_set)) <= 5`（允许 ±5 秒误差）。
     - 方案 B：若密码在注册时由 GUI 刚刚设置，直接记录设置完成时刻的 `SystemTime_to_UnixSeconds`，登录时验证 `abs_diff <= 5`。

#### [VULN-02] AAD 简单拼接缺少长度前缀（Canonicalization / 域分隔碰撞漏洞）
- **位置**：v2 第 4.1 节
  - `AAD_password = version || app || slot || alg || card_pub_fingerprint || SID || username || computer_name || password_last_set`
- **机理**：
  - `SID`（字符串形式）、`username`、`computer_name` 均为**可变长度字段**。
  - 直接用 `||` 无分隔符、无长度前缀拼接可变长字段，违反密码学 Canonicalization 基本原则。例如：`username = "alice"`, `computer_name = "pc1"` 与 `username = "alic"`, `computer_name = "epc1"` 拼接出的字节流完全相同。
- **修复方案**：
  - 所有 AAD 组装必须采用**确定性定长/带长度前缀编码**：固定宽度字段按 Big-Endian/Little-Endian 固定字节写入；所有可变长字节串（`SID`、`username`、`computer_name` 的 UTF-8 字节）必须前置 `u32_le` 字节长度（Length-Prefix Framing）。

#### [VULN-03] PC/SC 同步调用无超时保护，卡死时将冻结整个 `LogonUI.exe` 并锁死原生密码救援通道
- **位置**：v2 第 1 节不变量 8、第 4.3 节、第 6.1 节
- **机理**：
  - `ICredentialProviderCredential::GetSerialization` 在 `LogonUI.exe` 的 STA 线程中被同步调用。
  - 在 RDP 智能卡重定向（`[MS-RDPESC]`）场景下，如果客户端网络高丢包、USB 总线挂起、或卡片固件死锁，`SCardConnectW` / `SCardBeginTransaction` / `SCardTransmit` 可能**无限期挂起（或阻塞数分钟）**。
  - 一旦 `GetSerialization` 阻塞，整个 `LogonUI.exe` 界面冻结，用户**无法点击“登录选项”切换回 Windows 原生密码框**——直接破坏不变量 8（“保留原生密码登录作为救援通道，绝不把用户锁在门外”）。
- **修复方案**：
  - 在 `scard-core` 的 PC/SC 封装层引入**强制超时取消机制**：
    1. 每次认证建立独立的 `SCARDCONTEXT`。
    2. 启动一个轻量级 Watchdog 计时器（或工作线程执行 PC/SC 流水线，主线程 `recv_timeout(Duration::from_secs(8))`）。
    3. 一旦超过 **8 秒**（如 RDP 断线或卡片无响应），立即在外部调用 **`SCardCancel(hContext)`** 强制打断正在阻塞的 PC/SC 调用，终止事务并返回 `AuthError::Timeout`，立即释放 `LogonUI` 主线程。

#### [VULN-04] RS-Key 硬件 Provisioning 存在 3 处致命盲区（可导致 PIN 无限离线爆破 / 静默 DoS）
对照 RS-Key 官方 `production.md`、`threat-model.md` 和 `limitations.md`，v2 第 3.1 节遗漏了三个决定硬件绑定生死的关键步骤：
1. **遗漏 `rsk otp lock-page58` 与分区表签名 `scripts/pt.sh`（导致 Token2 快照回滚攻击，PIN 计数器可无限重置）**：
   - RS-Key `production.md` 明确指出：仅执行 `rsk otp burn` 而不执行 `rsk otp lock-page58`，OTP Page 58 依然可通过 BOOTSEL 读取！
   - 更严重的是（`threat-model.md` "Flash snapshot rollback"）：RP2350 没有单调计数器。如果固件镜像在 `picotool seal --sign` 之前**没有先运行 `scripts/pt.sh` 嵌入分区表**，攻击者拿到物理卡后进入 BOOTSEL，用 `picotool save` 备份 flash，猜 3 次 PIN 锁卡后用 `picotool load` 恢复快照，即可**无限次重置 PIV PIN 重试计数器**！
2. **默认固件未门控 `WRITE CONFIG`，本机任意普通进程可静默禁用 PIV Applet（持久性 DoS）**：
   - `threat-model.md` §1 明确警告：RS-Key 默认构建中，设备配置写入（CCID Management `WRITE CONFIG` / FIDO `CONFIG_WRITE`）**没有任何 PIN 或触摸门控（UNGATED）**。主机上任意能访问读卡器的低权限进程都可以发送一条指令禁用 PIV Applet，且写入 flash 持久化，导致锁屏彻底找不到 PIV 卡。
   - **修复**：必须编译并刷入 **`firmware-strict-config`** 构建变体，关闭未门控配置修改；同时在不需要 FIDO over CCID 时禁用无关接口。
3. **`ykman piv access change-management-key --protect` 会把 Management Key 托管在 PIN 下**：
   - `piv.md` 指出：`--protect`（或触屏版 *Protect mgmt key*）会把 Management Key 用 PIN 加密存在 `5FC109` (PRINTED) 中。一旦开启，**知道 6–8 位 PIN 的人就同时获得了 PIV 管理员权限（可删除或覆盖 9D 密钥）**。
   - **修复**：FamiliarSmartcard 的卡片**严禁使用 `--protect`**！Management Key 必须随机生成（24 或 32 字节 hex）并离线写在恢复单上，绝不存入卡内 `5FC109`。

#### [VULN-05] 静态 `S_enroll` 的密码等价性与事件响应缺失
- **位置**：v2 第 1 节不变量 1/2、第 2.2 节、第 4.3 节
- **机理**：
  - `FreshnessProven` 成功阻止了“无真卡的重放设备”，但第 8 步 `KeyUnwrapped` 发送给卡片的依然是注册时固定的 `eph_pub_enroll`，卡片返回的 `S_enroll = ECDH(card_priv_9d, eph_pub_enroll)` 是**跨生命周期恒定不变的静态字节串**。
  - 这意味着：**一旦宿主或 RDP 远程主机在某一次成功登录时被攻陷并截获了 APDU 响应中的 `S_enroll`（或内存中的 `DEK`），攻击者今后就不再需要这张 RS-Key 卡片，可以离线永久解密 `VaultBlob` 中的密码**（直到更换密码并重新 Enroll 生成新的 `eph_pub_enroll`）。
- **修复方案**：
  - 在威胁模型（第 2.3 节）中诚实声明：`S_enroll` 在数学上与长期静态 KEK 等价；`FreshnessProven` 防御的是“未发生过宿主失陷前提下的假卡/读卡器重放”，不提供“宿主单次失陷后的前向安全（Post-Compromise Security）”。
  - 增加**应急响应与轮换机制**：任何时候怀疑远程主机曾短暂失陷，必须通过 `enroll-gui` 点击“重新绑定（轮换随机密码 + 重新生成 `eph_priv_enroll` / `DEK`）”，单靠拔掉卡片不够。

---

### 2. 高优先级缺陷（P1 / High）

#### [VULN-06] 注册与恢复单流程顺序反置，断电/崩溃会直接把用户永久锁死
- **位置**：v2 第 3.2 节、第 8.2 节
- **机理**：
  - v2 第 8.2 节顺序是：① 生成 32–64 位随机密码 -> ② `NetUserSetInfo` 修改系统密码 -> ③ 打印/导出恢复单 -> ④ 写 Vault 并自检。
  - **致命缺陷**：一旦第 ② 步 `NetUserSetInfo` 执行成功，Windows 账户密码就已经变成了随机字符串。如果此时第 ③ 步打印机故障、GUI 崩溃、断电、或者第 ④ 步卡片自检失败退出，**内存中刚生成的随机密码随着 `Zeroizing` 被清零，恢复单没印出来，Vault 也没写入**——用户当场被永久锁死在系统外！
- **修复方案（强制两阶段原子事务顺序）**：
  1. 生成随机新密码 `P_new`（存于 `Zeroizing`）。
  2. **先连接卡片并完成 Vault 加密与卡片完整解密自检**（对 `P_new` 走完 `VaultLoaded -> ... -> CredentialDecrypted`，确认解出的明文与 `P_new` 完全一致）。此时还不调用 `LogonUserW`（因为系统密码还没改）。
  3. **强制向用户展示/打印恢复单**，并要求用户在界面上**手动输入恢复单上的密码后 6 位（或勾选二次确认码）**，证明离线备份确实已完成。
  4. 将新 Vault 写入 `VaultBlob.pending`。
  5. 调用 `NetUserSetInfo` 修改 Windows 密码为 `P_new`，立刻读取 `password_last_set` 更新并完成最终 `VaultBlob` 原子替换。
  6. 调用 `LogonUserW(LOGON32_LOGON_NETWORK)` 做最终端到端校验。

#### [VULN-07] PIV Attestation (`f9`) 被误当作防伪根，且 OTP 烧录在 Phase 0 顺序错误
- **位置**：v2 第 3.1 节第 5 条、第 11 节 Phase 0
- **机理**：
  1. RS-Key 文档（`piv.md` / `limitations.md`）明确说明：RS-Key 的 `f9` 槽位 Attestation CA 是**设备首次上电时在芯片内自签生成的 P-384 密钥**，不是厂商统一根证书签发的。如果不先把这把真实 RS-Key 的 `f9` CA 证书固定（Pinning）下来，任何运行 RS-Key 固件的仿冒 RP2350 开发板都能生成合法的 `f9` 自签名 Attestation 链！
  2. `production.md` 指出：`rsk otp burn` 之后，设备级救援 attestation 密钥会改变，且 OTP 烧录不可逆。如果在 Phase 0 一上来还没写好 `scard-core` 就把唯一的开发板烧死，一旦固件配置（如 `firmware-strict-config` 或 `VIDPID`）有误且丢失签名密钥，开发板直接报废。
- **修复方案**：
  - 将 OTP 烧录拆分为：**开发期（Phase 0–4）使用未烧录或测试板 + `--dry-run`**；**投产期（Phase 5）确认 `firmware-strict-config` + `pt.sh` 分区表无误后再正式烧录 OTP + Secure Boot**。
  - 在 `enroll-gui` 注册时，不仅校验 9D 证书公钥指纹，还应调用 `ATTEST (00 F9 00 9D)` 并校验证书由当前卡的 `f9` 签发、扩展 OID 中 `PIN policy == ALWAYS (0x03)`，同时将 `f9` 公钥指纹一并展示给用户核对。

#### [VULN-08] 两次 `VERIFY PIN` 的非原子计数器消耗与错误提示误导
- **位置**：v2 第 4.3 节第 5、7 步
- **机理**：
  - 因为 9D 设为 `PIN policy = ALWAYS`，每次登录会执行**两次** `VERIFY PIN`（第 5 步新鲜挑战前一次，第 7 步静态解封前一次）。
  - 如果第 5 步 `VERIFY` 成功（此时 retry counter 重置为 3），第 6 步新鲜 ECDH 成功，但在第 7 步第二次 `VERIFY` 时由于 USB 信号抖动/总线位翻转导致 APDU 校验错误或返回 `63 C2`，或者用户使用的是 Touch Policy = ALWAYS 但第二次没按按钮（返回 `6982`），CP 必须清晰区分“第 1 次验证失败”与“第 2 次验证/解封失败”，且**一旦第 1 次 `VERIFY` 返回 `63 Cx`（密码错误），绝不能执行第 2 次 `VERIFY`**（Typestate 已保证这一点，但必须在测试中钉死：单次错误 PIN 登录尝试最多只消耗 1 次 retry counter，绝不能消耗 2 次！）。

#### [VULN-09] 关闭 RDP NLA 暴露 Pre-Auth 攻击面与会话泄漏风险
- **位置**：v2 第 7.1 节
- **机理**：
  - 关闭 NLA (`UserAuthentication = 0`) 后，任何能连上 TCP 3389 端口的客户端都会直接触发服务端启动 `LogonUI.exe` 并加载 `familiar_cred_provider.dll`。
  - 攻击者无需任何凭据即可远程打满 RDP 连接槽位（耗尽服务端内存/会话 DoS），且直接暴露 Windows RDP 栈与自定义 CP 的 Pre-Auth 攻击面。
- **修复方案**：
  - 第 7.1 节必须把“建议防火墙限制”升级为**硬性前置条件**：关闭 NLA 的机器**严禁将 3389 暴露在局域网广播域或公网**，必须绑定在 WireGuard / Tailscale / IPSec 接口 IP 上，或配置 Windows 防火墙 IPsec 连接安全规则（要求预认证隧道）。

---

### 3. 中优先级与规范补全项（P2 / Medium）

- **[VULN-10] PIV APDU 精确报文与 Chaining / TLV 长度边界未写进 v2**：
  - v2 删掉了 v1 审计报告中的 APDU 规范表。
  - 必须补齐：`SELECT PIV` 完整 11 字节 AID、`VERIFY` 的 `0xFF` 8 字节填充与 ASCII 数字检查、`GENERAL AUTHENTICATE` 的 BER-TLV 精确字节（`00 87 11 9D 45 7C 43 82 00 85 41 <65-byte-uncompressed-P256-pub>`，注意 Yubico/NIST SP 800-73-4 中请求需要先放空响应标签 `82 00` 再放 `85 41 <pub>`！如果只发 `85 41`，标准 PIV 卡与 RS-Key 会拒绝或解析失败！）。
- **[VULN-11] ECDH 卡片返回的共享密钥/公钥合法性校验**：
  - 主机收到卡片返回的 32 字节 X 坐标（`7C 22 82 20 <32-byte-X>`）后，必须检查其不全为 `0x00`；在注册读取卡片 9D 公钥时，必须用 `p256::PublicKey::from_sec1_bytes` 验证该点确实位于 P-256 曲线上且非无穷远点。
- **[VULN-12] `SCardEndTransaction` 失败时的 PIN 会话残留兜底**：
  - v2 遗漏了 v1 审计要求的降级措施：若 `SCardEndTransaction(SCARD_RESET_CARD)` 返回错误（如读卡器驱动不支持软 reset），必须尝试 `SCARD_UNPOWER_CARD`；若仍失败，必须在断开前发送一条 `SELECT OpenPGP AID (00 A4 04 00 06 D2 76 00 01 24 01)` 强制卡片切换当前活动 Applet，从而在固件层销毁 PIV 会话状态。
- **[VULN-13] `VaultBlob` 反序列化 DoS 防护与注册表 ACL**：
  - DPAPI 解密前必须限制注册表读取的 `VaultBlob` 最大字节数（例如 `<= 4096` 字节），防止恶意构造超大注册表值在 `LogonUI.exe` 中触发 OOM Abort（`catch_unwind` 无法捕获 OOM）。
  - 明确 `HKLM\SOFTWARE\FamiliarSmartcard` 的 DACL：`SYSTEM:(F)`、`Administrators:(F)`，移除 `Users` 的读取权限（`LogonUI.exe` 与提权 helper 均以 `SYSTEM`/管理员运行，普通用户无需也不应能读取 `VaultBlob`）。

---

## 第二部分：待合并入 `ARCHITECTURE_AND_PLAN.md` 的 v2.1 补丁内容

> 说明：以下各节可直接替换或追加到 `ARCHITECTURE_AND_PLAN.md` 对应章节，将其升级为 **v2.1**。

---

### 补丁 1：新增《0. 版本修订与审计闭环追踪表》（插入第 1 节之前）

```markdown
## 0. 版本修订与审计闭环记录（v1 -> v2 -> v2.1）

| 审计编号 | 问题描述 | 闭合章节 | 状态 |
| :--- | :--- | :--- | :---: |
| **P0-1** | 静态 `Eph_Pub` 可被假卡重放 | 1(2), 4.3(6), 5 | ✅ 已闭合 |
| **P0-2** | `Eph_Priv_enroll` 若持久化则硬件绑定失效 | 1(1), 4.1, 4.2(7) | ✅ 已闭合 |
| **P0-3** | KERB 结构错误、缺少 `CredProtectW` 与 `Negotiate` | 6.2 | ✅ 已闭合 |
| **P0-4** | PC/SC 缺少事务锁与 Reset 失败的 Applet 切换兜底 | 1(3), 4.3, 4.5 | ✅ v2.1 补齐 |
| **P0-5** | RS-Key 硬件前提（`lock-page58`、`pt.sh`、`strict-config`、禁 `--protect`） | 2.3, 3.1, 11 | ✅ v2.1 补齐 |
| **VULN-01** | `usri3_password_age` 秒级抖动导致 AAD / 密码变更校验假失败 | 3.2(5), 4.1, 4.3(2) | ✅ v2.1 修复 |
| **VULN-02** | AAD 可变长字段无长度前缀拼接导致域碰撞 | 4.1 | ✅ v2.1 修复 |
| **VULN-03** | PC/SC 阻塞无 `SCardCancel` 超时，冻结 `LogonUI` 锁死救援通道 | 1(8), 4.5, 6.3 | ✅ v2.1 修复 |
| **VULN-05** | 静态 `S_enroll` 的长期密码等价性与失陷后密钥轮换流程 | 2.3, 8.2 | ✅ v2.1 补齐 |
| **VULN-06** | 先改系统密码后打恢复单/自检，崩溃时永久锁死用户 | 3.2, 8.2, 8.3 | ✅ v2.1 修复 |
| **VULN-10** | PIV `GENERAL AUTHENTICATE` `7C/82 00/85` 标准 TLV 与状态字规范 | 4.5 | ✅ v2.1 补齐 |
```

---

### 补丁 2：更新《2.3 关键残余风险》与《3.1 RS-Key / RP2350 Provisioning》

将第 2.3 节与第 3.1 节替换为以下内容：

```markdown
### 2.3 关键残余风险（必须写进文档）

1. **硬件物理边界**：RS-Key 是 **experimental / unaudited** 项目；RP2350 没有 secure element。仅在完成 `rsk otp burn` + `rsk otp lock-page58` + 嵌入分区表 (`scripts/pt.sh`) 的 Secure Boot 签名后，才能阻止通过 BOOTSEL 进行的 Flash Dump 和 PIN 计数器快照回滚攻击（Token2 Issue #37）。
2. **`S_enroll` 的密码等价性（无失陷后前向安全）**：虽然第 6 步 `FreshnessProven` 阻止了无卡重放，但第 8 步用于解封 DEK 的卡片 ECDH 响应 `S_enroll = ECDH(card_priv, eph_pub_enroll)` 是静态的。**一旦宿主或远程主机在某次成功登录时已处于失陷状态并记录了 `S_enroll` 与 `VaultBlob`，攻击者即可离线永久还原该密码**。怀疑主机曾失陷时，必须立即通过 GUI 重新绑定（轮换 Windows 密码并重新生成 `eph_pub_enroll`）。
3. **恢复单物理泄露风险**：纸质恢复单记载了 Windows 本地账户的明文随机密码。由于 Windows 原生密码 CP 始终开启作为救援通道，**任何人拿到纸质恢复单即可直接用密码登录，完全绕过 RS-Key**。恢复单必须视同最高机密离线锁存。
4. **远程主机可见 PIN 与中继风险**：远程 CP 方案中，PIN 经 RDP 加密通道到达远程主机内存；且远程主机通过 RDP 重定向访问客户端卡片，若远程主机被攻陷，可在用户插卡期间发起 APDU 中继。
5. **Rust 内存清零局限**：`Zeroizing` 可确保堆缓冲在 Drop 时清零，但无法消除编译器在栈上因按值 Move 产生的中间寄存器/栈帧残余，也无法清除 `LogonUI.exe` 传给 `SetStringValue` 的原始 COM 缓冲。

---

### 3.1 RS-Key / RP2350 Provisioning（分阶段执行，严禁在代码未定型前烧死 OTP）

> **警告**：OTP 熔丝烧录不可逆！**Phase 0–4 开发与联调阶段必须使用未锁定的开发板（或 `--dry-run`）**；仅在 Phase 5 全部测试通过后，对正式使用的板卡执行第 5 步不可逆固化。

1. **编译并刷入安全配置固件**：
   - 必须使用 **`firmware-strict-config`** 构建变体（拒绝未授权的 USB 主机通过 `WRITE CONFIG` 静默禁用 PIV Applet 造成持久化 DoS）。
   - 硬件必须为 **RP2350 A4 stepping**（修复 A2 的 E16/E20/E24 故障注入与 BootROM 漏洞）；长期高价值场景建议 **RP2354**（封装内 Flash，防御 QSPI XIP TOCTOU）或经认证的商业 PIV 密钥。
2. **修改全部默认凭据（严禁使用 `--protect`）**：
   - 修改 PIV **PIN**（6–8 位 ASCII 数字，避免弱口令）、**PUK**（8 位数字）。
   - 修改 **Management Key**（AES-256，32 字节随机 hex）：
     - **严禁使用 `--protect`**（`--protect` 会将 Management Key 用 PIN 加密存入 `5FC109`，导致知道 PIN 就拥有卡片管理权）。Management Key 必须离线记录在恢复单上，用毕即忘。
   - 显式确认 PIN/PUK 重试次数为 `3 / 3`。
3. **在 PIV `9D`（或专用 `82`–`95`）槽位 On-Card 生成 P-256 密钥**：
   - 算法：`ECCP256`（PIV Alg ID `0x11`）。
   - PIN Policy：**`ALWAYS`**（每次私钥操作前必须紧邻一次 `VERIFY`，操作完即失效）。
   - Touch Policy：默认 **`NEVER`**（兼顾 RDP 体验）；高安全场景可选 **`ALWAYS`**（注意：每次登录需按压 BOOTSEL 键 **2 次**，且在 RS-Key 上 `CACHED` 等同于 `ALWAYS`）。
   - 严禁从外部导入私钥（导入私钥无 Attestation，且可能留有外部副本）。
4. **提取并固定（Pinning）公钥与 Attestation 证书**：
   - 读取 `9D` 公钥，校验点位于 P-256 曲线上，计算 `SHA-256(uncompressed_sec1_pubkey)` 作为 `card_pub_fingerprint`。
   - 调用 `ATTEST` (`00 F9 00 9D`) 获取槽位证明证书，并导出 `f9` 槽位设备自签名 CA 证书；验证 `9D` 证明证书由该卡 `f9` 签发，且证书扩展中的 PIN Policy 确认为 `ALWAYS`。
5. **正式卡不可逆硬件固化（仅在 Phase 5 执行，严格按 `production.md` 顺序）**：
   - **Stage 1 (OTP Master Key)**：`rsk otp burn` -> 重启等待首次启动完成 pre-OTP 记录自动重加密与全盘 GC 擦除（切勿断电） -> **`rsk otp lock-page58`**（锁死 BOOTSEL 对 Page 58 的读取权限，此步漏掉则 Flash Dump 依然可解！）。
   - **Stage 2 (Secure Boot + 分区表围栏)**：
     - 离线生成并备份 `secp256k1` 签名私钥（丢失则永远无法升级固件）。
     - 编译 ELF 后，**必须在签名之前执行 `scripts/pt.sh` 嵌入分区表**（将 KV 存储区设为 `NSBOOT(-)`，阻止通过 BOOTSEL `picotool save/load` 回滚 Flash 快照来无限重置 PIN 计数器）。
     - 对包含分区表的 ELF 执行 `picotool seal --sign --hash ... --rollback 1`，再转为 UF2 刷入并验证启动。
     - 依次执行 `rsk secure-boot load-key` -> `harden` -> `enable` -> `lock`。
   - **Stage 3 (Anti-Rollback)**：刷入同版本的 `rsk-wipe`，执行 `rsk otp rollback-require`。
```

---

### 补丁 3：修复《4.1 数据结构（长度前缀 AAD 与时间戳）》与新增《4.5 PIV APDU 与 PC/SC 超时规范》

将第 4.1 节 AAD 与时间戳定义更新，并在第 4 节末尾新增 4.5 节：

```markdown
### 4.1 数据结构与确定性 AAD 编码（v2.1 修正）

（`VaultBlob` 字段保持不变，补充以下硬性编码与校验规则：）

1. **长度上限与防 OOM**：从注册表读取的 DPAPI 密文长度不得超过 **4096 字节**；DPAPI 解密后的 `VaultBlob` 明文长度必须精确等于固定头部 + 固定 256 字节密文的总长，超出或不足立即拒绝解析。
2. **密码定长填充**：UTF-16LE 编码（最多 **127 个 UTF-16 码元** / 254 字节）；前置 `u16_le` 字节长度（`0..=254` 且为偶数）；尾部填充 `0x00` 至固定 **256 字节**。
3. **带长度前缀的确定性 AAD（消除拼接歧义）**：
   所有可变长字符串均转换为 UTF-8 字节串，并以 `u32_le` 长度前缀包裹（记为 `LP(s) = len_u32_le(s) || utf8_bytes(s)`）：
   ```text
   AAD_wrap =
       "FamiliarSmartcard/v2/aad-wrap\0"
       || version (u8) || app (u8) || slot (u8) || alg (u8)
       || card_pub_fingerprint ([u8; 32])
       || LP(SID_string)

   AAD_password =
       "FamiliarSmartcard/v2/aad-pwd\0"
       || version (u8) || app (u8) || slot (u8) || alg (u8)
       || card_pub_fingerprint ([u8; 32])
       || LP(SID_string)
       || LP(username_lower)
       || LP(computer_name_upper)
       || vault.password_last_set (u64_le)   // 必须使用注册时写入 Vault 的静态值！
   ```
4. **`password_last_set` 的获取与比对容差（修复秒级抖动漏洞）**：
   - 注册时：计算 `enroll_last_set = current_unix_seconds() - (usri3_password_age as u64)`，作为静态 `u64` 存入 `VaultBlob.password_last_set` 并写入 `AAD_password`。
   - 登录时：重新读取当前账户的 `usri3_password_age`，计算 `current_last_set = current_unix_seconds() - (usri3_password_age as u64)`。
   - **容差判定**：若 `current_last_set.abs_diff(vault.password_last_set) > 5`（超过 ±5 秒容差），则判定为“Windows 密码已被外部修改”，立即返回 `AuthError::PasswordChanged_RebindRequired`；若在 ±5 秒内，则视为未修改，并使用 **`vault.password_last_set`** 组装 `AAD_password` 进行 AES-GCM 解密。

---

### 4.5 PIV APDU 精确报文、状态字与 PC/SC 超时/降级规范（v2.1 新增）

#### 1. 标准 PIV APDU 序列

- **SELECT PIV Application**：
  - 请求：`00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00 00`
  - 预期：`90 00`（校验返回的 FCI/APT 模板非空）。
- **VERIFY PIN（6–8 位 ASCII 数字 `'0'..'9'`）**：
  - 请求：`00 20 00 80 08 <8-byte-PIN-padded-with-0xFF>`
  - 示例（PIN `123456`）：`00 20 00 80 08 31 32 33 34 35 36 FF FF`
  - 状态字映射：
    - `90 00`：验证通过。
    - `63 CX`：PIN 错误，剩余 `X` 次机会（**立即终止流水线**，严禁发起第二次 `VERIFY`！返回剩余次数给 UI）。
    - `69 83`：PIN 已锁定（需使用 PUK 解锁）。
- **GENERAL AUTHENTICATE — P-256 ECDH（Slot `9D`，Alg `0x11`）**：
  - **注意（NIST SP 800-73-4 / Yubico PIV 规范）**：Dynamic Authentication Template (`7C`) 内**必须同时包含空的响应标签 `82 00` 和承载 65 字节未压缩公钥（`04 || X || Y`）的挑战标签 `85 41 <pub>`**！
  - 请求（共 74 字节）：
    `00 87 11 9D 45 7C 43 82 00 85 41 <65-byte-uncompressed-P256-pubkey> 00`
    （若使用 retired 槽位 `82`–`95`，将第 4 字节 `9D` 替换为 `vault.slot`）。
  - 响应（若返回 `61 XX`，必须循环发送 `00 C0 00 00 XX` (`GET RESPONSE`) 直至收到 `90 00`）：
    `7C 22 82 20 <32-byte-shared-secret-X> 90 00`
  - 校验：解析 `7C` -> `82`，长度必须恰好为 32 字节，且**不全为 `0x00`**。
  - 状态字映射：
    - `69 82`：安全状态不满足（PIN 未验证、已被上一次操作消耗、或 Touch 超时未按压）。
    - `6A 80` / `6A 86`：数据格式错误或非法曲线点。
    - `6A 88`：槽位无密钥。

#### 2. PC/SC 强制超时取消（防止冻结 `LogonUI`）

- 每次 `GetSerialization` 必须在独立工作线程中运行 `AuthPipeline`，主线程等待结果的最大超时为 **8 秒**（若启用了 Touch Policy = ALWAYS，设为 **18 秒**并在 UI 提示“请按压密钥按钮”）。
- 工作线程建立 `SCARDCONTEXT` 后，将其句柄共享给主线程的超时守卫。
- 一旦超时触发，主线程立即调用 **`SCardCancel(hContext)`** 强制唤醒并中止挂起的 `SCardConnectW` / `SCardBeginTransaction` / `SCardTransmit`，工作线程触发 Drop 清理并返回 `AuthError::Timeout`，保证 `LogonUI` 界面永不死锁，用户随时可切回原生密码登录。

#### 3. 事务结束与 Reset 失败的强制销毁兜底

`ScardCardHandle::drop` 必须按以下顺序清理卡片安全状态：
1. 调用 `SCardEndTransaction(hCard, SCARD_RESET_CARD)`。
2. 若返回非 `SCARD_S_SUCCESS`，立即尝试发送一条跨应用选择指令：`SELECT OpenPGP AID (00 A4 04 00 06 D2 76 00 01 24 01)`（RS-Key 固件规范：切换到另一个 Applet 会立即销毁 PIV 的 PIN 验证状态），随后调用 `SCardEndTransaction(hCard, SCARD_UNPOWER_CARD)`。
3. 调用 `SCardDisconnect(hCard, SCARD_RESET_CARD)`（若失败则传 `SCARD_UNPOWER_CARD`）。
4. 调用 `SCardReleaseContext(hContext)`。
```

---

### 补丁 4：修复《8.2 & 8.3 防锁死两阶段原子注册与密码轮换流程》

将第 8.2 节与第 8.3 节整合替换为以下严格顺序：

```markdown
### 8.2 & 8.3 防锁死两阶段原子注册流程（v2.1 强制顺序）

> **核心安全不变量**：在确认（1）卡片能成功解出新密码、且（2）用户已离线保存并核验纸质恢复单**之前**，**绝对禁止调用 `NetUserSetInfo` 修改 Windows 系统的真实密码**！

1. **前置检查（阶段 A）**：
   - 使用 `WTSQuerySessionInformation` 识别当前交互式会话用户名，由用户显式确认目标本地账户。
   - `NetGetJoinInformation` 确认机器处于 Workgroup 且目标为本地账户。
   - 连接 RS-Key，读取 `9D` 公钥并验证位于 P-256 曲线上；执行 `ATTEST` 验证密钥为卡内生成且 `PIN policy == ALWAYS`。
2. **生成新密码与内存预演自检（阶段 B — 此时不改系统密码）**：
   - 在 `Zeroizing` 内存中生成 32–64 位高熵随机密码 `P_new`（排除易混淆字符，便于纸质抄写/打印）。
   - 执行完整的 Enrollment 加密流程，在内存中生成候选 `VaultBlob`（此时立刻 `zeroize(eph_priv_enroll)`）。
   - **立即执行真卡解密自检**：提示用户输入一次 PIV PIN，用与锁屏完全一致的 `AuthPipeline`（连接 -> VERIFY #1 -> `FreshnessProven` -> VERIFY #2 -> `KeyUnwrapped` -> `CredentialDecrypted`）从候选 `VaultBlob` 中解密出 `P_decrypted`。
   - 常量时间比对 `P_decrypted == P_new`。**若不一致或卡片报错，直接中止！此时系统原密码分毫未动，用户零风险。**
3. **恢复单强制核验（阶段 C — 此时仍未改系统密码）**：
   - 展示或直接驱动打印机输出恢复单（包含：计算机名、用户名、SID、卡片公钥指纹、生成时间、明文密码 `P_new`）。**严禁提供“导出为本地 txt/pdf 文件”按钮**，防止明文落盘。
   - 弹出核验框：**要求用户看着纸质/离线恢复单，手动输入新密码的最后 6 位字符**。核验不通过则禁止进入下一步；用户此时点击“取消”依然不会改变系统原密码。
4. **原子提交与系统改密（阶段 D）**：
   - 调用提权 Helper（或当前提权进程）：
     1. 先将当前旧注册表项备份至 `VaultBlob.bak`（若存在）。
     2. 调用 `NetUserSetInfo`（level 1003）将 Windows 账户密码修改为 `P_new`，并设置 `UF_DONT_EXPIRE_PASSWD`（level 1008）。
     3. 立即调用 `NetUserGetInfo`（level 3）读取 `usri3_password_age`，计算静态 `password_last_set = now_unix_sec - age`。
     4. 用该 `password_last_set` 重新封装内层密码密文与 `AAD_password`（复用阶段 B 已验证的 `Wrapped_DEK`，无需再次动卡），经 DPAPI (`CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN`) 加密后写入 `VaultBlob.new`，读回校验无误后覆盖 `VaultBlob`。
     5. 调用一次 `LogonUserW(..., LOGON32_LOGON_NETWORK, ...)` 确认 Windows LSA 接受 `P_new`，立即 `CloseHandle`。
     6. 若第 4 步写注册表失败，立即在屏幕上醒目告警：“系统密码已更新为您手中的纸质恢复单密码，但 Vault 写入失败，请凭纸质恢复单登录并重试”。
```

---

### 补丁 5：补充《10.1 测试矩阵》与《13. 最终检查清单》新增项

在 10.1 节与第 13 节追加以下强制验收项：

```markdown
### 10.1 补充必测项（v2.1 新增）

- **ECDH 非法曲线点注入**：向卡片或解析器提供不在 P-256 曲线上的点（`y^2 != x^3 - 3x + b`）、无穷远点、截断的 SEC1 点，以及卡片返回全零共享密钥（`[0u8; 32]`），必须全部返回错误并中止。
- **两次 VERIFY 单次错误止损**：输入错误 PIN 时，必须在**第一次** `VERIFY` 返回 `63 C2` 后立即终止流水线，**绝不能触发第二次 `VERIFY`**（断言：一次错误登录尝试只扣除 1 次卡片 retry counter，不会连扣 2 次导致提前锁卡）。
- **`password_last_set` 秒级边界测试**：模拟 `now - usri3_password_age` 产生 ±3 秒抖动时，登录必须成功且 AAD 校验通过；模拟密码在 10 秒前被重置时，必须被拦截并提示“密码已更改，请重新绑定”。
- **AAD 域分隔防碰撞测试**：构造 `(username="alice", computer="pc1")` 与 `(username="alic", computer="epc1")`，断言两者生成的 `AAD_password` 字节流不同，交叉解密必败。
- **PC/SC 挂起超时与 `SCardCancel` 测试**：在 `MockTransport` 或代理读卡器中让 `SCardTransmit` 阻塞 30 秒，验证 `AuthPipeline` 在 8 秒内触发 `SCardCancel` 并返回 `AuthError::Timeout`，`LogonUI` 线程不被卡死。
- **注册中途崩溃防锁死测试**：在恢复单核验未通过、或卡片自检失败时强制终止 `enroll-gui`，验证 Windows 账户原密码未被修改。

---

### 13. 最终检查清单补充项（v2.1 新增）

- [ ] RS-Key 刷入 `firmware-strict-config`（防止未门控 `WRITE CONFIG` 禁用 PIV）。
- [ ] PIV Management Key 修改时**未使用 `--protect`**（防止 PIN 解锁管理权限）。
- [ ] Phase 5 正式烧录时完整执行：`rsk otp burn` -> **`rsk otp lock-page58`** -> **`scripts/pt.sh` 嵌入分区表** -> `picotool seal --sign` -> `secure-boot enable & lock` -> `rollback-require`。
- [ ] `GENERAL AUTHENTICATE` APDU 包含 `7C 43 82 00 85 41 <pub>` 完整 TLV，并处理 `61 XX` (`GET RESPONSE`)。
- [ ] `AAD_password` 与 `AAD_wrap` 所有可变长字段均带 `u32_le` 长度前缀；AAD 内使用 Vault 静态 `password_last_set`，比对使用 ±5 秒容差。
- [ ] PC/SC 具备 8 秒超时 + `SCardCancel` 机制；`Drop` 在 `SCARD_RESET_CARD` 失败时有 `SELECT OpenPGP AID` + `SCARD_UNPOWER_CARD` 兜底。
- [ ] `enroll-gui` 严格执行“先自检 + 先核验恢复单 -> 最后调用 `NetUserSetInfo` 改系统密码”的防锁死顺序。
- [ ] `HKLM\SOFTWARE\FamiliarSmartcard` 注册表 ACL 仅允许 `SYSTEM` 与 `Administrators` 访问；`VaultBlob` 读取限制 `<= 4096` 字节。
- [ ] 关闭 NLA 的远程主机已通过防火墙/VPN 严格隔离 3389 端口，未暴露于公网或不可信局域网。
```
