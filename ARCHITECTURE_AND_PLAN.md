# FamiliarSmartcard 架构设计与实施计划 v2.1

> **版本**：v2.1（2026-11-21）  
> **取代**：v2  
> **已定案决策**：
> 1. RS-Key **PIV 9D ECDH P-256**，PIN policy **ALWAYS**，on-card 生成。
> 2. **远程主机 Credential Provider + 关闭 RDP NLA**，通过 RDP 智能卡重定向访问客户端本地 RS-Key。
> 3. **Windows 本地账户**（Workgroup），不使用域账户或 Microsoft 账户。
>
> **审计依据**：
> - `SECURITY_AUDIT.md`（v1 审计）
> - `PLAN_V2_1_PATCH.md`（v2 深度补丁）
> - `PLAN_V2_1_REVIEW.md`（对补丁报告的审计）
>
> **一句话目标**：没有真实 RS-Key、正确 PIN、新鲜 ECDH 挑战，就无法还原 Windows 登录密码；同时保留原生密码登录，绝不把用户永久锁死。

---

## 0. v2.1 修订记录

| 编号 | 问题 | v2.1 处理 | 状态 |
| :--- | :--- | :--- | :---: |
| **P0-1** | 静态 `Eph_Pub` 可被假卡重放 | 新增 `FreshnessProven` 新鲜 ECDH 挑战 | ✅ |
| **P0-2** | `Eph_Priv_enroll` 若持久化则绑定失效 | 仅存 `Eph_Pub_enroll`；私钥用完即清零 | ✅ |
| **P0-3** | KERB 结构/CredProtect/Negotiate 错误 | 改用 `KERB_INTERACTIVE_UNLOCK_LOGON` + `CredProtectW` + `Negotiate` | ✅ |
| **P0-4** | PC/SC 事务、Reset 兜底、PIN 会话残留 | 事务 + `SCARD_RESET_CARD` + `SELECT OpenPGP` + `SCARD_UNPOWER_CARD` | ✅ |
| **P0-5** | RS-Key provisioning 盲区 | `lock-page58`、`pt.sh`、`firmware-strict-config`、禁 `--protect` | ✅ |
| **VULN-01** | `password_last_set` 秒级抖动 | AAD 用 vault 静态值；变更检测用 ±5 秒容差 | ✅ |
| **VULN-02** | AAD 可变长字段歧义 | 全部改为 `u32_le` 长度前缀 | ✅ |
| **VULN-03** | PC/SC 阻塞冻结 `LogonUI` | 每请求隔离执行单元 + 超时；helper 进程为硬保证 | ✅ |
| **VULN-04** | 默认固件 ungated `WRITE CONFIG` | `firmware-strict-config`；OTP/lock-page58/pt.sh | ✅ |
| **VULN-05** | 静态 `S_enroll` 无 post-compromise security | 写入威胁模型 + 轮换流程；补充中继风险 | ✅ |
| **VULN-06** | 先改系统密码后打恢复单会锁死 | 两阶段原子注册；先自检/核验恢复单，最后改密 | ✅ |
| **VULN-07** | `f9` attestation 被误当厂商根 | 首次注册固定 `f9` CA；OTP 烧录后重新固定 | ✅ |
| **VULN-08** | 两次 VERIFY 的 retry 消耗 | 第一次失败立即终止，绝不第二次 VERIFY | ✅ |
| **VULN-09** | 关闭 NLA 暴露 pre-auth 面 | 3389 只允许 VPN/IPsec 流量，禁止公网/广播域 | ✅ |
| **VULN-10** | PIV ECDH APDU 缺 `82 00` | 精确报文：`Lc=0x47`，`7C 45 82 00 85 41 <65>` | ✅ |
| **VULN-11** | ECDH 共享密钥/公钥未校验 | `from_sec1_bytes` + 非全零检查 | ✅ |
| **VULN-12** | Reset 失败无兜底 | `SELECT OpenPGP` + `SCARD_UNPOWER_CARD` | ✅ |
| **VULN-13** | Vault 反序列化 DoS / ACL | 4096 字节上限；仅 SYSTEM/Administrators | ✅ |

---

## 1. 安全不变量

1. **无卡不可解**：vault 不得包含能脱离 RS-Key 还原密码的材料；`Eph_Priv_enroll` 绝不持久化。
2. **新鲜性**：每次登录先通过新的 ECDH 挑战（`FreshnessProven`），才允许静态 `Eph_Pub_enroll` 解封。
3. **静态 `S_enroll` 的残余风险必须诚实声明**：它不提供 post-compromise security；怀疑宿主失陷时，必须重新绑定并轮换密码。
4. **单事务**：从 `SELECT PIV` 到最终 ECDH 全部在同一个 `SCardBeginTransaction` 内；结束用 `SCARD_RESET_CARD`。
5. **PIN ALWAYS**：9D 每次私钥操作前必须 `VERIFY`；一次登录两次 VERIFY；第一次失败立即终止，绝不第二次。
6. **失败闭合**：任何一步失败立即终止；不生成 KERB、不返回 `CPGSR_RETURN_CREDENTIAL_FINISHED`、不自动重试。
7. **不自动登录**：`pbAutoLogon` / `pbAutoLogonWithDefault` 永远 `FALSE`；不设置默认 CP。
8. **密码不落盘**：明文密码只在 `Zeroizing` 内存中；KERB 前必须 `CredProtectW`；不写日志/崩溃转储。
9. **保留原生密码**：自定义 CP 与原生密码 CP 并存；DLL/注册表损坏时仍可登录。
10. **静态 AAD 时间戳**：`AAD_password` 使用 vault 中的 `password_last_set`；登录时的动态值只用于 ±5 秒容差比较。
11. **两阶段注册**：在卡片自检和恢复单核验完成之前，绝不调用 `NetUserSetInfo` 修改真实密码。
12. **PC/SC 不冻结 LogonUI**：每次认证在隔离执行单元中运行，硬超时后 CP 必须返回；helper 进程超时可直接终止。
13. **远程主机可信假设**：远程 CP 方案中 PIN 会到达远程主机；远程主机被攻陷等于 PIN/密码暴露。

---

## 2. 威胁模型

### 2.1 In Scope

- 无卡、错卡、假卡重放、错误 PIN、PIN 锁定。
- 卡片中途拔出、RDP 断线、读卡器忙、PC/SC 挂起。
- vault 被复制到另一台机器（DPAPI 失败）。
- 逻辑 bug 跳过布尔检查（仍缺卡片数学材料）。
- 密码被修改后提交旧密码（应被容差检测拦截）。
- 注册过程中断电/崩溃（不得先改真实密码）。

### 2.2 Out of Scope

- 已攻陷的宿主（Administrator/SYSTEM 恶意软件）：密码最终交给 `lsass.exe`。
- 已攻陷的远程主机：PIN 会到达远程主机。
- 已攻陷的 RDP 客户端/中间人。
- RP2350 物理攻击：decap、FIB、故障注入、功耗/EM 侧信道。
- 恶意/被替换的 RS-Key 固件；未审计的 RP2350 安全边界。
- **APDU 中继**：假读卡器把 APDU 转发给真实卡片，Freshness 也会通过。
- 成功登录后的完整响应/内存捕获。
- 恢复单被拍照/复印：拿到恢复单即可绕过 RS-Key。

### 2.3 关键残余风险

1. **硬件物理边界**：RS-Key experimental/unaudited；RP2350 无 secure element。只有 `rsk otp burn` + `rsk otp lock-page58` + `pt.sh` + Secure Boot 后，flash dump/BOOTSEL 回滚才被有效阻止。
2. **`S_enroll` 静态等价于长期 KEK**：宿主/远程主机在一次成功登录时被攻陷并记录 `S_enroll`，攻击者可离线永久解密该 vault，直到重新绑定/换密码。
3. **中继**：Freshness 不防 APDU 中继；Touch/PIN 是主要限速手段。
4. **恢复单**：记录明文随机密码；拿到纸质恢复单即可绕过 RS-Key。必须视同最高机密离线锁存。
5. **Rust 清零局限**：`Zeroizing` 清堆缓冲，但无法消除寄存器/栈 Move 残余、COM `SetStringValue` 的原始缓冲。
6. **远程 PIN 暴露**：远程 CP 方案中 PIN 经 RDP 加密通道到达远程主机内存。

---

## 3. 硬件与账户前置条件

### 3.1 RS-Key / RP2350 分阶段 provisioning

> **警告**：OTP 烧录不可逆。Phase 0–4 使用未锁定开发板/`--dry-run`；Phase 5 全部测试通过后才固化正式板。

#### 开发阶段（Phase 0–4）

- 使用未烧 OTP 的测试板；不要拿唯一正式板做固件试验。
- 可先刷 `firmware-strict-config`（或至少记录默认 `firmware` 的 ungated `WRITE CONFIG` 风险）。
- 修改 PIV PIN/PUK/Management Key；**严禁 `--protect`**（它把管理密钥托管在 PIN 下，PIN 即管理权限）。
- 在 9D on-card 生成 P-256：
  - `ECCP256`（PIV Alg `0x11`）
  - PIN policy **ALWAYS**
  - Touch policy 默认 `NEVER`；高安全可选 `ALWAYS`（每次登录两次触摸；RS-Key 上 `CACHED` 等同 `ALWAYS`）
  - 禁止导入外部私钥
- 读取 9D 公钥，校验 P-256 曲线点，保存 SHA-256 指纹。
- 调用 `ATTEST (00 F9 00 9D)`，验证 9D 证书由当前卡 `f9` 签发，PIN policy `0x03`；**固定 `f9` CA**（它是设备首次上电自签，不是厂商根）。
- 做一次 `rsk backup export`（FIDO seed；PIV/OpenPGP 不迁移）。

#### 生产阶段（Phase 5）

严格按 RS-Key `production.md` 顺序：

1. `rsk backup export`（如尚未）。
2. `rsk otp burn`。
3. 重启，等待首次启动的 pre-OTP 记录迁移/全盘 GC；**切勿断电**。
4. `rsk otp lock-page58`（只 burn 不 lock，Page 58 仍可被 BOOTSEL 读取）。
5. 重新固定 `f9` attestation（burn 后设备 attestation 公钥会变）。
6. `scripts/pt.sh` 嵌入分区表（必须在签名之前）。
7. `picotool seal --sign --hash ... --rollback 1`（ELF，不是 UF2；签名后转 UF2）。
8. `rsk secure-boot load-key` → `harden` → `enable` → `lock`。
9. 可选 `rsk otp rollback-require`；`rsk-wipe` 同版本重签。
10. 验证 `picotool info -a` 显示 `signature: verified`、store 为 `NSBOOT(-)`；负极测试未签名 UF2 被拒绝。

> 若使用 OpenPGP 而非 PIV：burn 后要 verify 一次 PW3 并重设 reset code，否则 PIN-derived 记录仍留在 pre-burn 根上。本项目 PIV-only 也建议执行同类检查。

### 3.2 Windows 本地账户

- `NetGetJoinInformation` 确认 Workgroup；域/Microsoft 账户拒绝或强警告。
- 由 GUI 生成 32–64 位随机密码，排除易混淆字符，便于纸质抄写。
- **两阶段注册**（见第 8 节）：先卡片自检 + 恢复单核验，最后才 `NetUserSetInfo`。
- 设置 `UF_DONT_EXPIRE_PASSWD`（level 1008，保留原 flags）。
- 记录静态 `password_last_set = current_unix_seconds - usri3_password_age`（注册时一次）。
- 登录时动态计算 `current_last_set`，仅用于 `abs_diff <= 5` 的变更检测；AAD 始终用 vault 静态值。
- 密码变更/过期/账户锁定：`ReportResult` 明确提示；不要自动重试。

---

## 4. 密码学协议

### 4.1 VaultBlob 与确定性 AAD

```text
VaultBlob = DPAPI_MACHINE(
  version: u8
  app: u8                 // PIV = 1
  slot: u8                // 0x9D（或 82–95）
  alg: u8                 // P-256 = 1
  card_pub_fingerprint: [u8; 32]
  eph_pub_enroll: [u8; 65]     // 只有公钥
  wrapped_dek: Vec<u8>
  wrap_nonce: [u8; 12]
  wrap_tag: [u8; 16]
  salt: [u8; 32]
  nonce: [u8; 12]
  ciphertext: Vec<u8>          // 固定 256 字节填充密码
  tag: [u8; 16]
  password_last_set: u64       // 注册时静态值
  created_at: u64
)
```

- **输入上限**：从注册表读取的 DPAPI 密文 <= **4096 字节**；解码后总长 <= 4096。
- **密码填充**：UTF-16LE，最多 127 个码元；前置 `u16_le` 字节长度（0..=254，偶数）；尾部 `0x00` 填充至 256。
- **长度前缀**：

```text
LP(s) = u32_le(byte_len) || utf8_bytes(s)

AAD_wrap =
  "FamiliarSmartcard/v2/aad-wrap\0"
  || version || app || slot || alg
  || card_pub_fingerprint
  || LP(SID)

AAD_password =
  "FamiliarSmartcard/v2/aad-password\0"
  || version || app || slot || alg
  || card_pub_fingerprint
  || LP(SID)
  || LP(lower(username))
  || LP(upper(computer_name))
  || password_last_set (u64_le)   // vault 静态值
```

- `KEK = HKDF-SHA256(S_enroll, salt, "FamiliarSmartcard/v1/wrap")`。
- `Wrapped_DEK = AES-256-GCM(KEK, wrap_nonce, DEK, AAD_wrap)`。
- 密码密文 = `AES-256-GCM(DEK, nonce, padded_password, AAD_password)`。
- 所有随机数来自 OS CSPRNG。
- **`Eph_Priv_enroll` 只存在栈上，计算完 `S_enroll` 后立即清零并丢弃。**

### 4.2 注册（候选 vault，不改系统密码）

1. 读取目标 SID/username/computer；确认 Workgroup。
2. 连接卡片，SELECT PIV，读 9D 公钥，校验曲线点，计算指纹；显示给用户确认。
3. 生成随机 `DEK`、`salt`、`nonce`、`wrap_nonce`。
4. 加密 `P_new`，生成候选 `VaultBlob`；生成临时 P-256 密钥对，计算 `S_enroll`、`KEK`、`Wrapped_DEK`。
5. 立即清零 `Eph_Priv_enroll`、`S_enroll`、`KEK`、明文副本。
6. 用候选 vault 走完整 `AuthPipeline` 自检，解出 `P_decrypted`，常量时间比较 `P_decrypted == P_new`。
7. **自检失败则中止；此时系统密码未变，用户零风险。**
8. 展示/打印恢复单，要求用户手动输入密码最后 6 位确认；不提供本地 txt/pdf 导出。此时可保留 DEK 在 `Zeroizing` 中供阶段 D 使用；若用户取消，立即清零 DEK 与 `P_new`。
9. 写入 `VaultBlob.pending`。
10. `NetUserSetInfo` 改系统密码；读取 `usri3_password_age` 计算新静态 `password_last_set`；用保留的 DEK（或重新动卡）以新 AAD 重新加密 `P_new`，写入最终 `VaultBlob`，读回校验。
11. `LogonUserW(LOGON32_LOGON_NETWORK)` 最终验证；关闭 token。
12. 最终写入失败：醒目告警“系统密码已是恢复单密码，但 Vault 写入失败”；用户凭恢复单登录后重试。

> **注意**：`Wrapped_DEK` 本身不能直接重新加密密码；阶段 D 必须有明文 DEK（保留或重新动卡）。这是 v2.1 明确要求。

### 4.3 登录

```text
1. 读取 VaultBlob；DPAPI 解开；解析；校验版本/长度/AAD 元数据。
2. 读取当前账户 password_last_set；与 vault 静态值 abs_diff > 5 -> PasswordChanged。
3. PC/SC：context -> reader -> connect(shared, T0|T1) -> begin transaction
4. SELECT PIV AID；读 9D 公钥/指纹；必须匹配。
5. VERIFY PIN #1。
6. FreshnessProven：新 P-256 临时密钥对 -> GENERAL AUTHENTICATE -> 与期望值常量时间比较；失败即终止。
7. VERIFY PIN #2（第一次 ECDH 已消耗 ALWAYS PIN）。
8. KeyUnwrapped：静态 Eph_Pub_enroll -> S_enroll -> HKDF -> AES-GCM 解 Wrapped_DEK。
9. CredentialDecrypted：AES-GCM 解密码；校验长度/UTF-16。
10. CredProtectW -> KERB_INTERACTIVE_UNLOCK_LOGON -> CoTaskMemAlloc。
11. 结束事务/断开：SCARD_RESET_CARD；失败则 SELECT OpenPGP + SCARD_UNPOWER_CARD。
12. 清零 PIN、密码、DEK、共享密钥。
```

### 4.4 为什么能防“第 101 次 bug”

- 无卡：拿不到 `S_fresh`/`S_enroll`；内存中没有 KEK/DEK。
- 假卡重放：无法通过新鲜 ECDH 比较。
- 错卡：GCM tag 失败。
- vault 被复制：DPAPI 失败；即使解开，没有卡片也无法得到 `S_enroll`。
- `Eph_Priv_enroll` 不落盘：vault 本身不能算出 `S_enroll`。
- 任何一步 `Err` 消费当前 Typestate；无法构造下一步。
- `CredProtectW` 失败即 fail closed，不退明文。

### 4.5 PIV APDU、超时与 Reset 兜底

#### 4.5.1 精确 APDU

```text
SELECT PIV:
  00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00

VERIFY PIN（6–8 位 ASCII 数字，补 0xFF 到 8 字节）:
  00 20 00 80 08 31 32 33 34 35 36 FF FF

GENERAL AUTHENTICATE — P-256 ECDH（9D，Alg 0x11）:
  00 87 11 9D 47
  7C 45
    82 00
    85 41 <65-byte uncompressed P-256 public key: 04 || X || Y>

  响应：7C 22 82 20 <32-byte shared secret> 90 00
```

> **关键**：`82 00` 不能省；`Lc=0x47`，`7C` 长度 `0x45`；总 APDU 不含 Le 为 76 字节。报告 v2.1 草稿里的 `45 / 43` 是错的，按那个发送会 `6700`/`6A80`。

状态字：
- `63 CX`：PIN 错误，剩余 X 次；立即终止，绝不第二次 VERIFY。
- `69 83`：PIN 锁定；提示 PUK。
- `69 82`：安全状态不满足（PIN 未验证/被消耗/Touch 超时）。
- `6A 80` / `6A 86`：数据/曲线错误。
- `6A 88`：槽位无密钥。

#### 4.5.2 超时

- `GetSerialization` 不得直接阻塞 `LogonUI` STA。
- 首选：**独立 helper 进程**（SYSTEM）执行 PC/SC + 解密；CP 通过命名管道发 SID/PIN，主线程 8 秒（Touch ALWAYS 18 秒）等待；超时 `TerminateProcess` helper。
- 备选：worker 线程 + `SCardCancel(hContext)` + 超时；`SCardCancel` 只是 best-effort，不保证打断驱动层 `SCardConnect`/`SCardTransmit` 挂起；必须用阻塞代理读卡器实测。
- 超时/取消返回 `AuthError::Timeout`；卡片 session 由 Drop 清理。

#### 4.5.3 Reset 兜底

`ScardCard::drop`：

1. `SCardEndTransaction(hCard, SCARD_RESET_CARD)`。
2. 失败：发送 `SELECT OpenPGP AID (00 A4 04 00 06 D2 76 00 01 24 01)`，再 `SCardEndTransaction(hCard, SCARD_UNPOWER_CARD)`。
3. `SCardDisconnect(hCard, SCARD_RESET_CARD)`；失败再 `SCARD_UNPOWER_CARD`。
4. `SCardReleaseContext(hContext)`。

---

## 5. Rust Typestate

```text
VaultLoaded
  -> CardConnected
  -> PinVerified
  -> FreshnessProven
  -> PinVerifiedForUnwrap
  -> KeyUnwrapped
  -> CredentialDecrypted
  -> KerbPacked
```

- 每步按值消费 `self`；字段私有；无 `Clone`。
- `CardConnected` 持有 `ScardCard` + `ScardContext`，字段顺序保证 card 先于 context drop。
- `PinVerified::prove_freshness()` 执行新鲜 ECDH；`FreshnessProven::verify_pin_for_unwrap(pin)` 执行第二次 VERIFY；`PinVerifiedForUnwrap::unwrap_dek()` 执行静态 ECDH。
- `KeyUnwrapped` 的 `dek` 是 `Zeroizing<[u8;32]>`；`CredentialDecrypted` 的密码是 `Zeroizing<String>`。
- 任何错误都消费当前状态并触发 Drop/reset。

---

## 6. Windows Credential Provider

### 6.1 接口与行为

实现 `ICredentialProvider`、`ICredentialProviderSetUserArray`、`ICredentialProviderCredential`、`ICredentialProviderCredential2`。

- 支持 `CPUS_LOGON`、`CPUS_UNLOCK_WORKSTATION`；其余 `E_NOTIMPL`。
- 只为有 vault 的 SID 显示 tile；`GetCredentialCount` 设 `pbAutoLogonWithDefault = FALSE`。
- 字段：标题、PIN（`CPFT_PASSWORD_TEXT`，不启用 reveal）、登录按钮、状态文本。
- `SetStringValue` 只接受数字；PIV 6–8 位；`Zeroizing<Vec<u16>>`。
- `SetSelected` 设 `*pbAutoLogon = FALSE`。
- `SetDeselected`/`ReportResult`/`GetSerialization` 结束/`Drop` 清零 PIN。
- `GetSerialization`：
  - 空 PIN -> 失败提示，不碰卡片。
  - 执行 Typestate；成功 `CredProtectW` + `KERB_INTERACTIVE_UNLOCK_LOGON` + `CoTaskMemAlloc`。
  - 失败 `CPGSR_NO_CREDENTIAL_NOT_FINISHED` + 状态文本；不自动重试。
- `ReportResult` 映射 `STATUS_LOGON_FAILURE`、`STATUS_ACCOUNT_LOCKED_OUT`、`STATUS_PASSWORD_EXPIRED`、`STATUS_ACCOUNT_DISABLED`。

### 6.2 KERB

```text
KERB_INTERACTIVE_UNLOCK_LOGON:
  MessageType = KerbInteractiveLogon | KerbWorkstationUnlockLogon
  LogonDomainName = 计算机名（本地账户）
  UserName = 用户名
  Password = CredProtectW(password)
  LogonId = 0  // Winlogon 填
```

- 认证包：`NEGOSSP_NAME_A`（`Negotiate`）。
- `CredProtectW` 失败 -> fail closed。
- 失败释放所有 `CoTaskMemAlloc`。

### 6.3 COM/FFI

- `#[implement]`；内部 PIN 状态用 `RefCell`（单 STA）或 `Mutex`。
- 每方法 `catch_unwind(AssertUnwindSafe(...))`；输出指针先置空；panic hook 不打印秘密。
- `catch_unwind` 不能捕获 AV/栈溢出/OOM；减少 unsafe、隔离 PC/SC、fuzz 解析器。
- 不设置默认 CP、不自动登录。

### 6.4 部署

- `C:\Program Files\FamiliarSmartcard\familiar_cred_provider.dll`。
- 架构匹配 `LogonUI.exe`（x64/ARM64）；静态 CRT；`panic=unwind`。
- 导出 `DllGetClassObject`/`DllCanUnloadNow`；`IClassFactory`；`ThreadingModel=Apartment`。
- 注册：
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
  - `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`
  - 64 位视图；ACL 仅 SYSTEM/Administrators。
- 代码签名；Smart App Control/WDAC/AppLocker 需 VM 验证。
- 提供注册/卸载/救援脚本；VM 测试 DLL 丢失/注册键损坏时原生密码可登录。

---

## 7. RDP

### 7.1 硬性前置条件

- 服务端 Windows Pro/Enterprise；`SCardSvr` 运行。
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 0`（关闭 NLA）。
- **3389 严禁暴露公网/不可信局域网**；必须只允许 WireGuard/Tailscale/IPSec 接口或 Windows 防火墙 IPsec 认证流量。
- 账户锁定、审计日志、RDP 连接限制。

### 7.2 客户端

- `mstsc` -> 本地资源 -> 智能卡。
- `.rdp`：`enablecredsspsupport:i:0`、`authentication level:i:0`。
- 客户端智能卡服务/读卡器驱动正常。

### 7.3 行为与风险

- 远程 `LogonUI` 加载 CP；`SCardEstablishContext(SCARD_SCOPE_USER)` 按会话重定向。
- 远程主机可见 PIN（已接受风险）。
- 远程主机不可信 -> 不要用远程 CP；考虑客户端 `CPUS_CREDUI` + NLA（vault 在客户端，PIN 不出客户端）。

---

## 8. 注册 GUI（两阶段原子流程）

### 8.1 用户/SID

- `WTSQuerySessionInformation` 获取交互式会话用户；`LookupAccountNameW` 得 SID；`ConvertSidToStringSidW`。
- `NetGetJoinInformation` 确认 Workgroup；拒绝域/Microsoft 账户。
- 用户显式确认目标账户。

### 8.2 阶段 A：前置检查

- 读 9D 公钥，校验 P-256；`ATTEST` 验证 on-card + PIN policy ALWAYS；固定 `f9` CA。
- 读当前 `usri3_password_age`，计算旧 `password_last_set`。

### 8.3 阶段 B：候选 vault + 自检（不改系统密码）

- 生成 `P_new`、候选 vault；自检解出 `P_decrypted == P_new`。
- 自检失败 -> 中止；系统密码未变。
- 可保留 `DEK` 在 `Zeroizing` 中供阶段 D；用户取消则清零。

### 8.4 阶段 C：恢复单核验（仍不改密码）

- 打印/展示恢复单：计算机名、用户名、SID、卡指纹、时间、`P_new`。
- 禁止导出本地 txt/pdf；打印 spool 风险需提示。
- 要求用户手动输入密码最后 6 位；失败不得继续。

### 8.5 阶段 D：原子提交

1. 备份旧 `VaultBlob` 到 `.bak`。
2. 写 `VaultBlob.pending`。
3. `NetUserSetInfo` 改密；`UF_DONT_EXPIRE_PASSWD`。
4. 读 `usri3_password_age`，计算新静态 `password_last_set`。
5. 用保留的 DEK（或重新动卡）以新 AAD 重新加密 `P_new`。
6. 写最终 `VaultBlob`，读回校验；失败则保留 `.bak`。
7. `LogonUserW(LOGON32_LOGON_NETWORK)` 验证；关闭 token。
8. 清零 DEK/P_new/PIN。

> 若第 3 步成功但第 6 步失败：系统密码已是恢复单密码，Vault 写入失败；必须醒目告警，用户凭恢复单登录后重试。

### 8.6 GUI 技术

- 默认原生 Win32 最小界面；`Edit` + `ES_PASSWORD` + `SecureZeroMemory`。
- 若用 egui，必须验证文本缓冲生命周期；提交/失焦清零。
- 不以管理员收集密码，除非必要；可拆“非提权收集/加密 + 提权写注册表/改密码”。
- 禁用 WER 本地转储包含密码；不写日志。

---

## 9. 工程结构

```text
D:\Projects\FamiliarSmartcard\
├── Cargo.toml
├── ARCHITECTURE_AND_PLAN.md
├── SECURITY_AUDIT.md
├── PLAN_V2_1_PATCH.md
├── PLAN_V2_1_REVIEW.md
├── scripts/
└── crates/
    ├── scard-core/        # rlib：PC/SC、PIV、vault、crypto、Typestate、enroll、probe
    ├── cred-provider/     # cdylib：COM CP
    └── enroll-gui/        # bin：原生 Win32 注册/自检
```

- `scard-core`：`#![forbid(unsafe_code)]`；PC/SC/DPAPI/注册表 FFI 隔离。
- `cred-provider`：`cdylib`；`panic=unwind`；`+crt-static`；导出 COM 入口。
- 依赖：`windows` 0.62、`zeroize`、`aes-gcm`、`p256`、`hkdf`、`sha2`、`subtle`、`rand`、`thiserror`、`hex`；不需要 `rsa`。
- `cargo fmt --check`、`clippy -D warnings`、`cargo audit`、`cargo deny`。

---

## 10. 测试矩阵

### 10.1 核心/协议

- 正常注册 -> 登录 -> 密码正确。
- 无卡/错卡/卡忙/读卡器消失。
- PIN 错误 1/2/3 次；锁定；PUK 解锁。
- **第一次 VERIFY 失败 -> 绝不第二次**；一次错误只扣 1 次 retry。
- 重放：mock 返回旧 `S_enroll`/`S_fresh` -> 失败。
- 假卡返回随机/全零共享密钥 -> 失败。
- 只有 vault、无卡 -> 失败。
- 篡改 vault 任一字段 -> 失败。
- `password_last_set` ±3 秒 -> 成功；10 秒前改密 -> 拦截。
- AAD 长度前缀碰撞测试。
- 任何阶段 Err/panic -> 不构造 `KeyUnwrapped`/`CredentialDecrypted`。
- Reset 后直接私钥操作 -> `6982`。
- `SCardEndTransaction` 失败 -> OpenPGP SELECT + unpower 兜底。
- PC/SC 挂起 30 秒 -> 8 秒超时返回；`LogonUI` 不冻结。

### 10.2 CP/系统

- logon/unlock 的 `MessageType`/`LogonId`。
- `CredProtectW` 失败 -> 不成功。
- 空/非数字/超长 PIN；Unicode/控制字符。
- `pbAutoLogon`/`pbAutoLogonWithDefault` 永远 FALSE。
- `ReportResult` 映射锁定/过期/密码错误；清零 PIN。
- COM panic -> HRESULT；不崩溃。
- 注册/卸载/救援；DLL 丢失；原生密码回退。
- RDP 连接/锁屏/解锁/断线；NLA 开关；智能卡重定向。
- 密码修改 -> 失败提示；备份密码可登录并重新绑定。
- 注册中途崩溃 -> 系统密码未变。

---

## 11. 实施阶段

### Phase 0：开发板与 provisioning

- 未烧 OTP 测试板；`firmware-strict-config`；改 PIN/PUK/mgmt key；9D P-256 ALWAYS；f9 pin。
- 验收：`ATTEST` 通过；拔卡/错卡无法解密。

### Phase 1：`scard-core`

- Typestate、PIV APDU（含 `82 00`）、vault、DPAPI、AAD 长度前缀、超时/兜底。
- 验收：10.1 全部通过。

### Phase 2：真实 PC/SC / RDP 重定向

- 事务、两次 VERIFY、reset 兜底、RDP 智能卡重定向。
- 验收：本地/RDP 完成 ECDH；拔卡/断线安全失败；reset 后 `6982`。

### Phase 3：`enroll-gui`

- WTS 用户/SID、随机密码、两阶段注册、恢复单、自检、密码变更检测。
- 验收：注册崩溃不锁死；自检失败不覆盖 working vault；恢复单可救援。

### Phase 4：`cred-provider`

- COM、KERB、CredProtect、ReportResult、helper/超时、注册/卸载。
- 验收：锁屏/解锁/RDP；空 PIN/错 PIN/无卡/错卡；原生密码回退。

### Phase 5：生产固化

- OTP burn/lock-page58/pt.sh/seal/secure boot/rollback；重新 pin f9。
- 验收：完整测试矩阵；救援演练；无明文日志；无自动登录。

---

## 12. 决策记录

| 决策 | 选择 | 理由 |
| :--- | :--- | :--- |
| 卡片协议 | PIV 9D ECDH P-256 | PIN ALWAYS 每次操作消费 PIN；reset 清晰；避免 RSA padding oracle。 |
| PIN 策略 | ALWAYS | PIN 不长期驻留；代价两次 VERIFY。 |
| Touch | 默认 NEVER；可选 ALWAYS | RDP 两次触摸不便；PIN + 持有为主；高安全可开 ALWAYS。 |
| 远程 | 远程 CP + 关闭 NLA | NLA 不支持第三方 CP；满足远程锁屏目标。 |
| 账户 | 本地账户 | 密码生命周期可控；域/Microsoft 会破坏 vault。 |
| 密码 | 随机 32–64 位，永不过期，纸质恢复单 | 避免用户改密导致 vault 过期；保留救援。 |
| GUI | 原生 Win32 最小界面 | 减少依赖和密码副本。 |
| 硬件 | RP2350 开发；高价值用认证密钥 | 无 secure element、未审计；OTP 烧录是 at-rest 前提。 |

---

## 13. 最终检查清单

- [ ] `Eph_Priv_enroll` 不落盘；无 `serde`/registry/log 输出。
- [ ] `FreshnessProven` 在 `KeyUnwrapped` 之前；失败不可绕过。
- [ ] 9D P-256、PIN ALWAYS、on-card、专用槽位、attestation、f9 pin。
- [ ] 两次 VERIFY 与 PIN ALWAYS 匹配；第一次失败不第二次。
- [ ] `SCardBeginTransaction` / `SCardEndTransaction(SCARD_RESET_CARD)` / reset 兜底。
- [ ] KERB `KERB_INTERACTIVE_UNLOCK_LOGON` + `CredProtectW` + `Negotiate`。
- [ ] 无自动登录；`pbAutoLogon`/`pbAutoLogonWithDefault` FALSE。
- [ ] `password_last_set` 静态 AAD + ±5 秒变更检测。
- [ ] 两阶段注册；先自检/恢复单，最后 `NetUserSetInfo`。
- [ ] `GENERAL AUTHENTICATE` 含 `82 00`，`Lc=0x47`，`7C 45`，处理 `61xx`。
- [ ] PC/SC 超时/helper；`SCardCancel` 边界已测试；reset 兜底。
- [ ] Vault 输入 <=4096；AAD 全长度前缀；共享密钥非全零。
- [ ] `firmware-strict-config`；禁 `--protect`；OTP burn/lock-page58/pt.sh/seal/secure boot。
- [ ] 3389 仅 VPN/IPsec；远程主机可信假设已记录。
- [ ] DLL 部署到 Program Files、架构匹配、静态 CRT、签名、注册/救援脚本。
- [ ] 测试矩阵全部通过；VM 救援演练；无明文日志。
