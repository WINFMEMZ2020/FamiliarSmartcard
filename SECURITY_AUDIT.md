# FamiliarSmartcard 计划审计报告

- **审计对象**：`ARCHITECTURE_AND_PLAN.md`（2026-11-21 版本）
- **审计范围**：Windows Credential Provider V2、PC/SC、RDP 智能卡重定向、RS-Key PIV/OpenPGP、Rust 工程与密码学协议
- **审计结论**：**方向正确，但不能按当前版本直接开工。** 当前计划有 **5 个阻断级（P0）问题**，其中“静态 `Wrapped_DEK` 可重放”和“`Eph_Priv` 若被持久化则硬件绑定失效”会直接破坏你最在意的安全属性。修正这些 P0 后，整体架构是可行的。

---

## 0. 审计依据

本次审计对照了以下一手资料，而不是仅凭经验判断：

1. Microsoft Credential Provider 官方示例与 `GetSerialization` 文档：
   - <https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider>
   - <https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-getserialization>
2. Microsoft 关于 RDP 与自定义 Credential Provider 的说明：
   - <https://learn.microsoft.com/en-us/archive/blogs/winsdk/rdc-and-custom-credential-providers>
3. Microsoft 关于 RDP 智能卡重定向的说明：
   - <https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-and-remote-desktop-services>
4. RS-Key 固件的 PIV / OpenPGP / 限制与威胁模型文档：
   - <https://github.com/TheMaxMur/RS-Key/blob/main/docs/guides/piv.md>
   - <https://themaxmur.github.io/RS-Key/guides/openpgp.html>
   - <https://github.com/TheMaxMur/RS-Key/blob/main/docs/limitations.md>
   - <https://github.com/TheMaxMur/RS-Key/blob/main/docs/threat-model.md>
5. Yubico PIV ECDH 的 `GENERAL AUTHENTICATE` TLV 说明：
   - <https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/auth-key-agree.html>
6. PC/SC `SCardBeginTransaction` / `SCardEndTransaction` / `SCardDisconnect` 语义：
   - Microsoft Win32 Smart Card API 文档。

---

## 1. 结论摘要

### 1.1 计划中做得好的部分

这些设计方向是正确的，应保留：

- **Rust Typestate + 所有权消费**：用类型系统强制“上一步结果被消费后才能进入下一步”，比 C++ 的 `bool is_authenticated` 可靠得多。
- **零后台线程、单次同步流水线**：Credential Provider 的 `GetSerialization` 本来就是同步调用，在这个边界内做单线程流水线是合理且简单的。
- **Fail-fast + `ZeroizeOnDrop`**：任何一步不符合预期就终止，敏感内存自动清零。
- **“密码学绑定而非布尔判断”**：不把“是否验证通过”作为唯一放行条件，而是让没有硬件就无法还原密码，这是正确的核心思想。
- **保留 Windows 原生密码登录**：多 Credential Provider 并存，避免把自己锁死。
- **不使用明文密码做本地存储**：双层信封加密的方向正确。
- **不做自动登录**（计划中虽未明说，但必须坚持）：`pbAutoLogon` 和 `pbAutoLogonWithDefault` 永远为 `FALSE`。

### 1.2 问题分级

| 级别 | 数量 | 含义 |
| :--- | :---: | :--- |
| **P0 阻断** | 5 | 不修正就会破坏核心安全属性，或导致实现方向错误，不能开工。 |
| **P1 高** | 5 | 不修正会导致锁屏不稳定、密码生命周期问题、RDP 不可用或部署失败。 |
| **P2 中** | 4 | 影响可维护性、可测试性、兼容性和长期安全性，建议在实现前定案。 |

---

## 2. P0 阻断级问题

### P0-1：静态 `Wrapped_DEK` + 静态 `Eph_Pub` 可被重放，硬件绑定可被绕过

**计划原文**：

> 注册阶段生成临时密钥对 `(Eph_Priv, Eph_Pub)`，通过 ECDH 算出共享密钥，经 HKDF 派生 KEK，用 AES-256-GCM 封装 DEK……登录阶段将 `Wrapped_DEK` 中的挑战参数（临时公钥 `Eph_Pub`）发送给 RS-Key，RS-Key 返回原始共享密钥，主机经 HKDF 解封出 DEK。

**问题**：

1. 登录时发送的是**注册时生成的静态 `Eph_Pub`**，不是每次登录新生成的挑战。卡片返回的共享密钥 `S_enroll` 也是静态的。
2. 攻击者只要记录一次成功的 APDU 交换（或者做一个会重放响应的假读卡器/假卡片），就可以在**没有真实私钥**的情况下返回同一个 `S_enroll`。主机会派生出同一个 KEK，解密 `Wrapped_DEK`，再解密密码。
3. 这正好命中你担心的场景：**“没有真实密钥参与，但服务判断凭证 OK”**。当前的 Typestate 只能保证“代码按顺序调用”，不能保证“卡片响应是新鲜的”。

**修正方案（必须做）**：

在 `PinVerified` 和 `KeyUnwrapped` 之间增加一个 **`FreshnessProven`** 阶段。每次登录都生成一个**新的临时 ECDH 密钥对**，让卡片对新的临时公钥做一次 ECDH，主机用自己新生成的临时私钥和卡片公钥计算期望值，并与卡片返回值做**常量时间比较**。只有比较通过，才允许进入静态 `Eph_Pub_enroll` 的解封阶段。

```text
Stage3PinVerified
  └─► Stage4FreshnessProven
        let (eph_priv_fresh, eph_pub_fresh) = P256::generate();
        let expected = ecdh(eph_priv_fresh, card_pub);
        let actual   = card.general_authenticate_ecdh(slot, &eph_pub_fresh)?;
        if !constant_time_eq(expected, actual) {
            return Err(AuthError::CardReplayOrWrongKey);
        }
        zeroize(eph_priv_fresh, expected, actual);
  └─► Stage5KeyUnwrapped
        let s_enroll = card.general_authenticate_ecdh(slot, &eph_pub_enroll)?;
        let kek      = hkdf_sha256(s_enroll, salt, info);
        let dek      = aes_256_gcm_open(kek, wrapped_dek)?;
        zeroize(s_enroll, kek);
  └─► Stage6CredentialDecrypted
        let password = aes_256_gcm_open(dek, nonce, ciphertext, aad)?;
        zeroize(dek);
```

**为什么这样能防重放**：

- 假卡片无法对**新的** `eph_pub_fresh` 计算出正确的 ECDH 共享密钥；它最多重放旧的 `S_enroll`，但旧值与主机新算出的 `expected` 不匹配，立即失败。
- 只有真实卡片持有私钥，才能返回正确的 `expected`。
- 静态解封阶段仍然可能被重放，但它在 `FreshnessProven` 之后；重放者无法通过前一步。

**OpenPGP 的等价做法**：

- OpenPGP 的 `PSO:DECIPHER` 返回的是**解密后的会话密钥**，不是裸 ECDH 共享密钥。每次登录生成一个新鲜的 ECDH 密文（内含随机会话密钥），让卡片解密并返回该会话密钥，与主机期望值比较；通过后再发送静态密文解出 DEK。
- 注意：OpenPGP RSA 的 `PSO:DECIPHER` 是 PKCS#1 v1.5，存在 padding oracle；**优先使用 ECDH（X25519 或 P-256），不要用 RSA**。

**测试要求**：

- 用 mock card 重放上一次的响应，必须得到 `AuthError::CardReplayOrWrongKey`。
- 用错误卡片返回任意共享密钥，必须失败。
- 用正确卡片但错误的 `eph_pub_fresh`，必须失败。
- 任何失败路径都不能构造出 `Stage5/Stage6`。

---

### P0-2：`Eph_Priv` 绝不能持久化，否则硬件绑定直接失效

**计划原文**：

> 生成临时密钥对 `(Eph_Priv, Eph_Pub)`，通过 ECDH 算出共享密钥……

**问题**：

注册阶段生成临时密钥对后，主机需要计算一次 ECDH 来封装 DEK。但**注册完成后必须立即销毁 `Eph_Priv`**，只保存 `Eph_Pub_enroll` 和 `Wrapped_DEK`。

如果实现者把 `Eph_Priv` 也存进注册表/DPAPI blob（例如为了“以后重新计算共享密钥”），那么攻击者拿到 vault 后，可以用 `Eph_Priv + card_pub` 自己算出 `S_enroll`，**完全不需要卡片**。这会让整个“硬件密码学绑定”变成摆设。

**修正方案（必须做）**：

- 注册阶段：`Eph_Priv` 只存在于栈上，计算完共享密钥后立即 `zeroize` 并 `drop`。
- 持久化字段只允许：`Eph_Pub_enroll`、`Wrapped_DEK`、`salt`、`nonce`、`ciphertext`、`tag`、`card_pub_fingerprint`、`app/slot/alg`、`version`、`password_last_set` 等。
- 登录阶段：**绝不允许**从本地材料计算 `S_enroll`；`S_enroll` 只能来自卡片响应。
- 代码审查检查项：搜索 `eph_priv`，确认没有任何 `serde` 字段、注册表写入、日志输出或 `Clone`。

**测试要求**：

- 只拿 vault（不含卡片）尝试解密，必须失败。
- 把 vault 复制到另一台机器，必须因 DPAPI 失败。
- 把 vault 中的 `Eph_Pub_enroll` 替换为攻击者自己的公钥，必须因 GCM tag 失败。

---

### P0-3：KERB 结构用错，且密码没有用 `CredProtectW`

**计划原文**：

> 将用户名、计算机名与解密出的 Windows 明文密码打包进 `KERB_INTERACTIVE_LOGON` 连续内存块（`CoTaskMemAlloc`）……

**问题**：

1. Microsoft 官方 CP 示例在 **logon 和 unlock 两种场景都使用 `KERB_INTERACTIVE_UNLOCK_LOGON`**，只是 `MessageType` 不同：
   - `CPUS_LOGON` → `KerbInteractiveLogon`
   - `CPUS_UNLOCK_WORKSTATION` → `KerbWorkstationUnlockLogon`
   - `LogonId` 置 0，由 Winlogon 填充。
   计划里只写 `KERB_INTERACTIVE_LOGON`，在 unlock 场景会构造错误。
2. 官方示例在 `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION` 下会调用 `CredProtectW` 加密密码，再把**受保护的字符串**放进 KERB 结构。计划里写的是“明文密码”直接打包，这会不必要地把明文暴露在序列化缓冲区中。
3. 认证包应使用 `NEGOSSP_NAME_A`（`"Negotiate"`），不是 `MICROSOFT_KERBEROS_NAME_A`；本地账户没有 Kerberos。

**修正方案（必须做）**：

- 使用 `KERB_INTERACTIVE_UNLOCK_LOGON`，按场景设置 `MessageType`，`LogonId = 0`。
- 调用 `CredProtectW(FALSE, password, ..., protected, ...)`；失败就**fail closed**，绝不回退明文。
- 用 `LsaConnectUntrusted` + `LsaLookupAuthenticationPackage(NEGOSSP_NAME_A)` 获取包 ID，`LsaDeregisterLogonProcess` 关闭。
- 序列化缓冲区用 `CoTaskMemAlloc`，成功后所有权交给 Windows；失败时 `CoTaskMemFree`。
- 设置 `pcpcs->clsidCredentialProvider`；成功才返回 `CPGSR_RETURN_CREDENTIAL_FINISHED`。

参考代码结构（Rust 伪代码）：

```rust
let protected = cred_protect_w(&password)?; // 失败则 fail closed
let mut kiul = KERB_INTERACTIVE_UNLOCK_LOGON::default();
kiul.Logon.MessageType = match cpus {
    CPUS_UNLOCK_WORKSTATION => KerbWorkstationUnlockLogon,
    CPUS_LOGON => KerbInteractiveLogon,
    _ => return Err(...),
};
kiul.Logon.LogonDomainName = domain;
kiul.Logon.UserName = username;
kiul.Logon.Password = protected;
// LogonId 保持 0，由 Winlogon 填
let blob = pack_kerb_interactive_unlock_logon(&kiul)?; // CoTaskMemAlloc
pcpcs.ulAuthenticationPackage = lookup_negotiate_auth_package()?;
pcpcs.clsidCredentialProvider = CLSID_FAMILIAR_SMARTCARD;
*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
```

**测试要求**：

- logon 和 unlock 两种场景分别构造，检查 `MessageType` 和 `LogonId`。
- `CredProtectW` 失败时，`GetSerialization` 不能返回成功。
- 序列化缓冲区长度、字符串偏移、空终止符对齐正确（`UNICODE_STRING.Length` 不含 NUL）。
- 失败路径释放所有 `CoTaskMemAlloc`。

---

### P0-4：单线程不等于没有并发；PC/SC 必须用事务并保证 PIN 会话被清除

**计划原文**：

> 零多线程……从物理根源上杜绝数据竞争……每次点击重试或重新认证，均从零创建全新的 PC/SC 会话……`SCardDisconnect(SCARD_RESET_CARD)`。

**问题**：

1. 你的代码是单线程，但**其他进程**（Windows 智能卡服务、GPG/OpenSC、其他应用）仍可能同时访问同一张卡。没有 `SCardBeginTransaction` 时，另一个进程可能在你 `VERIFY` 之后、`GENERAL AUTHENTICATE` 之前插入 APDU，或复用你刚建立的 PIN 会话。
2. PIV 9D 的默认 PIN 策略是 **ONCE per session**；如果你没有正确 reset，PIN 会话可能一直有效，其他进程可以蹭用。
3. OpenPGP 的 PW1 验证状态更持久：官方文档明确说，PW1 在第一次签名后对整个会话有效，直到拔卡或**选择另一个应用**才结束；`forcesig` 只影响签名，不影响解密。仅靠 `SCardDisconnect(SCARD_RESET_CARD)` 需要验证是否真的清除了状态。
4. `SCardEndTransaction` / `SCardDisconnect` 的返回值必须检查；reset 失败时不能假装成功。

**修正方案（必须做）**：

```text
SCardEstablishContext(SCARD_SCOPE_USER)
SCardListReadersW
SCardConnectW(SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
SCardBeginTransaction
  SELECT AID
  VERIFY PIN
  fresh ECDH
  static unwrap
SCardEndTransaction(SCARD_RESET_CARD)
SCardDisconnect(SCARD_RESET_CARD)
SCardReleaseContext
```

- 使用 `SCARD_SHARE_SHARED`，不要用 exclusive；否则 RDP 重定向或其他应用会冲突。
- 整个多 APDU 序列必须在同一个事务内。
- 结束事务时使用 `SCARD_RESET_CARD`；如果失败，降级尝试 `SCARD_UNPOWER_CARD`，并记录错误。
- 如果 `SCardEndTransaction` 失败，下一次连接前显式 `SELECT` 另一个应用（如 OpenPGP/PIV/OATH）来强制结束上一个应用的 PIN 会话，再 reset。
- **PIV 9D 在生成密钥时设置 `--pin-policy ALWAYS`**，不要用默认的 ONCE。这样每次私钥操作前都必须重新 VERIFY，即使进程被杀，PIN 也不会长期驻留。
- 如果使用 OpenPGP DEC 槽位，解密完成后显式选择另一个应用（例如 PIV 或 OATH AID），再断开；否则 PW1 会话可能保留。
- 处理 `SCARD_E_SHARING_VIOLATION`、`SCARD_W_REMOVED_CARD`、`SCARD_W_RESET_CARD`、`SCARD_E_NO_SMARTCARD`、`SCARD_E_READER_UNAVAILABLE` 等错误，给出明确提示。

**关键测试**：

- 解密成功后断开连接，重新连接并直接尝试 `GENERAL AUTHENTICATE`/`PSO:DECIPHER`，必须返回 `6982`（安全状态不满足）。
- 在 `VERIFY` 和 `GENERAL AUTHENTICATE` 之间由另一个进程插入 APDU，验证事务是否阻止。
- 拔卡、RDP 断线、读卡器忙、reset 失败等路径都不能返回密码。

---

### P0-5：RS-Key 的硬件安全前提没有写进计划，当前 RP2350 不能直接当作“可信硬件”宣传

**计划原文**：

> RP2350 芯片内的私钥……硬件密码学绑定……

**问题**：

RS-Key 官方文档明确说明：

- 项目是 **experimental and unaudited**。
- **没有 secure element**；RP2350 的 OTP/secure boot/glitch detector 是真实存在的，但 decap、微探针、FIB、故障注入、功耗/EM 侧信道不在防护范围内。
- PIV 私钥在静止时是 AES-256-GCM sealed 的，但**只有在 OTP master key 被 fuse 之后，flash dump 才不能还原密钥材料**；在 burn 之前，seal 的根来自芯片内部状态，拥有 flash + 芯片的攻击者可以重建。
- OpenPGP 的 PIN-derived 记录在 burn 之后，直到对应 PIN 下一次 VERIFY 之前，仍留在较弱的根上；PW3 如果还是默认值，flash dump + 公开芯片序列号可以直接打开 DEK 副本。
- RSA 私钥路径是项目自己的实现，**unaudited**；OpenPGP `PSO:DECIPHER` 的 RSA 版本存在 padding oracle。
- TRNG 未经特性化；没有 NIST ESV/ENT 认证。
- 默认 PIV management key、PIN、PUK 都是公开默认值；不修改等于未配置。

**修正方案（必须做）**：

在计划中加入“硬件 provisioning”章节，至少包括：

1. **烧录 OTP master key**，启用 secure boot；设置 anti-rollback（如果使用）。
2. 使用 **A4 stepping** 板；长期建议 RP2354（in-package flash）或经过认证的 PIV 安全密钥（YubiKey 5 等）。RP2350 开发板只用于开发/测试。
3. 修改 PIV PIN、PUK、management key；不要把 management key 存盘。
4. 在卡内**生成**密钥（不要导入），并验证 PIV attestation；导入的密钥无法证明未被复制。
5. 使用 **PIV 9D ECDH P-256**，PIN policy `ALWAYS`，touch policy 按需；不要用 RSA。
6. 为 FamiliarSmartcard 使用**专用槽位**（9D 或 retired 82–95），不要和邮件/S/MIME 共用。
7. 明确威胁模型：**不防**物理拆解、侧信道、被攻陷的宿主、恶意固件、被攻陷的 RDP 客户端/服务端。它防的是：无卡、错卡、假卡重放、vault 被盗（无卡）、逻辑 bug 绕过、PIN 错误、RDP 断线等。
8. 如果用于生产/高价值账户，改用经过认证的硬件密钥；RP2350 只作为个人实验/开发平台。

**测试/验收**：

- 在 burn 前和 burn 后分别做 flash dump 检查（仅在自有设备上，注意不要破坏设备）。
- `ykman piv info` / `gpg --card-status` 确认 PIN/PUK/mgmt key 已改、retry counter 正常、key 是 on-card generated。
- 拔卡后无法解密；错卡无法解密；PIN 错误 3 次后锁定；PUK 可解锁。

---

## 3. P1 高优先级问题

### P1-1：COM 层并不是“UI 只读”，`SetStringValue` 会保存 PIN；`catch_unwind` 也挡不住 AV/栈溢出

**问题**：

- `ICredentialProviderCredential::SetStringValue` 会在用户每输入一个字符时被调用，CP 必须把 PIN 存在对象里，直到 `GetSerialization`。计划里“UI 线程只能读取验证线程的状态，绝不能修改”与 COM 实际模型不符。
- `#[implement]` 生成的方法签名通常是 `&self`，内部状态需要 `RefCell`（单 STA）或 `Mutex`（更保守）；这不是“多线程”，但确实存在可变状态。
- `std::panic::catch_unwind` 只能捕获 Rust panic；**不能捕获 access violation、栈溢出、OOM abort、`panic=abort`**。如果 `unsafe` FFI 或解析器踩内存，`LogonUI.exe` 仍可能崩溃。
- `GetStringValue` 返回的 PIN 副本由 LogonUI 通过 `CoTaskMemFree` 释放，CP 无法清零那份内存。

**修正方案**：

- 明确区分：
  - **认证流水线**：无状态、每次 `GetSerialization` 从零开始、Typestate 消费。
  - **COM 凭据对象**：只保存 `cpus`、用户 SID、PIN 字段、状态文本；PIN 用 `Zeroizing<Vec<u16>>`，在 `SetDeselected`、`ReportResult`、`GetSerialization` 结束、`Drop` 时清零。
- `SetStringValue` 只接受数字（PIV 6–8 位；OpenPGP 6–127），限制长度，拒绝控制字符。
- `GetSerialization` 开始时复制 PIN 到 `Zeroizing`，结束后立即清零对象中的 PIN；不要缓存 PIN 用于重试。
- 所有 COM 方法外层用 `guard!` 宏包 `catch_unwind(AssertUnwindSafe(...))`，把 `Err` 和 panic 转成 `HRESULT`；输出指针先置空，避免 COM 调用方读到未初始化值。
- 设置 panic hook，只记录错误类型/位置，不打印 PIN、密码、共享密钥。
- **不要依赖 `catch_unwind` 保证“绝不崩溃”**。减少 `unsafe`，把 PC/SC FFI 隔离到小模块，严格校验长度/指针；对 vault/APDU 解析做 fuzzing。
- 如果要求“即使 core 崩了也不能拖垮 LogonUI”，考虑**独立 helper 进程**：CP 只做 COM 薄壳，通过命名管道把 SID/PIN 发给以 SYSTEM 运行的 helper，helper 做 PC/SC + 解密，返回受保护的结果；CP 设置超时。代价是 IPC 和新攻击面；收益是崩溃隔离和超时控制。对这个项目，建议至少把该方案作为备选评估。

**测试**：

- 输入超长 PIN、非数字、空 PIN、Unicode、控制字符，不能 panic。
- 在每一阶段注入 panic，确认 COM 返回失败而不是进程崩溃。
- 用 fuzzer 跑 vault 解析和 APDU 响应解析。

---

### P1-2：密码生命周期没有设计；密码一改，vault 立刻过期

**问题**：

- 计划假设 Windows 密码长期不变。但用户可能通过 Ctrl+Alt+Del 改密码、密码策略可能要求过期、Microsoft 账户可能在线改密。
- 一旦密码变了，vault 里还是旧密码，卡片登录必然失败；如果用户忘了新密码，可能被锁在外面（虽然原生密码框可用，但需要知道新密码）。
- 计划里“把密码设为 32 位随机密码”只是建议，没有纳入流程。

**修正方案**：

1. **推荐本地账户**，不要用 Microsoft 账户/域账户；在 GUI 中检测 `NetGetJoinInformation`，如果不是 WORKGROUP，给出明确警告。
2. 注册时由 GUI 生成 32–64 位随机密码，调用 `NetUserSetInfo`/`NetUserChangePassword` 设置；设置“密码永不过期”；打印/导出恢复单（含计算机名、用户名、密码、卡指纹、日期），要求离线保存。
3. 在 vault 中保存 `password_last_set`（来自 `NetUserGetInfo` 的 `usri3_password_age` 或等价时间）；每次登录前比较；不一致就返回“Windows 密码已更改，请使用备份密码登录后重新绑定”，不要盲目提交旧密码。
4. 注册时用 `LogonUserW`（建议 `LOGON32_LOGON_NETWORK`，避免创建完整交互式会话）验证一次密码；失败则拒绝写入 vault；提示可能计入账户锁定次数。
5. 如果密码过期/账户锁定，`ReportResult` 显示对应状态；不要自动重试。
6. 文档中明确：**改密码后必须重新绑定**；GUI 提供“重新绑定”按钮，先验证当前密码，再重新加密。

**测试**：

- 改密码后卡片登录必须失败并给出正确提示。
- 用备份密码可以登录并重新绑定。
- 账户锁定/密码过期时提示正确。

---

### P1-3：RDP + NLA 的取舍没有写清楚；远程锁屏方案会把 PIN 送到远程主机

**问题**：

- Microsoft 明确说明：**NLA 不能处理第三方 Credential Provider**；要让远程锁屏使用自定义 CP，必须关闭 NLA（服务端 `UserAuthentication=0`，客户端 `.rdp` 中 `enablecredsspsupport:i:0`）。
- 关闭 NLA 会扩大攻击面：未认证连接就能到达远程 `LogonUI`。
- 远程 CP 方案中，PIN 会通过 RDP 智能卡重定向送到**远程主机**的 `LogonUI`/`WinSCard`，远程主机可以看到 PIN（虽然 RDP 通道加密）。如果远程主机不可信，这是不可接受的。
- 计划没有提到 Windows 版本（RDP 服务端需要 Pro/Enterprise）、防火墙、账户锁定、VPN/网关等。

**修正方案**：

- 明确这是**个人可信远程主机**方案；在文档中写明“远程主机被攻陷 = PIN/密码暴露”。
- 网络层必须加：VPN/Tailscale/ZeroTier、防火墙白名单、RDP 端口限制、账户锁定策略、审计日志；不要直接暴露 3389。
- 服务端关闭 NLA 的具体注册表：`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 0`；客户端 `.rdp` 加 `enablecredsspsupport:i:0`。
- 保留原生密码登录；不要把自定义 CP 设为默认，不要自动登录。
- 如果必须保留 NLA，或远程主机不可信，考虑**客户端侧 CP**：在客户端实现 `CPUS_CREDUI`，用本地卡片解密目标账户密码，交给 CredSSP；NLA 保持开启，PIN 不离开客户端。代价是 vault 在客户端，远程主机仍会看到密码（CredSSP 本来就会送密码），但至少 PIN 不经过远程主机。
- 明确 RDP 智能卡重定向要求：服务端 `SCardSvr` 运行、组策略允许智能卡重定向、客户端 `mstsc` 勾选“智能卡”、客户端有读卡器驱动。
- 在 VM 中测试 `SCardEstablishContext` 的作用域（建议 `SCARD_SCOPE_USER`）和会话内重定向行为；不要假设 `SCARD_SCOPE_SYSTEM` 也会重定向。

**测试**：

- 本地锁屏、RDP 锁屏、RDP 解锁、RDP 断线重连。
- NLA 开启时自定义 CP 不应出现（预期）；NLA 关闭时出现。
- 客户端不勾选智能卡时，CP 报“未检测到密钥”，不能崩溃。

---

### P1-4：GUI 的“当前用户/SID”在提权后可能是错的；`LogonUserW` 有副作用

**问题**：

- GUI 自动请求管理员权限后，进程 token 是管理员账户；`GetUserName`/`WindowsIdentity` 可能返回**提权账户**，而不是交互式登录的目标用户。计划说“自动识别当前登录的 Windows 用户名与 SID”，这在 UAC 提权场景下是错的。
- `LogonUserW` 使用错误密码会累计账户锁定计数；GUI 的“自检 100 次”如果密码错，会把账户锁掉。
- 如果 GUI 用 `egui`/`eframe`，文本框/事件队列可能保留密码副本，`Zeroize` 只能清你自己那份。

**修正方案**：

- 用 `WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName/WTSDomainName)` 获取**交互式会话**的用户；用 `LookupAccountNameW` 得到 SID；用 `ConvertSidToStringSidW` 存 registry key。
- 或者 GUI 非提权运行，只负责收集/加密，另起一个提权 helper 只做 registry 写入和 `NetUserSetInfo`；避免密码进入提权进程的复杂生命周期。
- 让用户明确选择目标账户；不要假设“当前进程用户 = 目标用户”。
- `LogonUserW` 只验证一次；建议 `LOGON32_LOGON_NETWORK`；立即 `CloseHandle`；失败时提示可能计入锁定；不要自动重试。
- 自检使用正确的 PIN/密码；如果失败，停止并提示，不要循环 100 次。
- GUI 推荐**原生 Win32 最小界面**（`Edit` + `ES_PASSWORD` + `SecureZeroMemory`），或至少自定义密码控件；如果坚持 `egui`，需要确认其文本缓冲的生命周期，并在失焦/提交后清空。
- 禁用 WER 本地转储或至少不要把密码写进日志；敏感缓冲区用 `VirtualLock`（可选）。

**测试**：

- 标准用户 + UAC 提权管理员账户，确认绑定的是交互式用户，不是管理员。
- 多用户快速切换，确认 SID 正确。
- 错误密码一次后停止，账户未被反复锁定。

---

### P1-5：部署与注册细节缺失，按当前路径注册很可能在锁屏加载失败

**问题**：

- 计划把编译产物写成 `familiar_cred_provider.dll`，但没有说部署位置。`LogonUI.exe` 以 SYSTEM 运行，不能依赖 `D:\Projects\...\target\release` 这种用户目录/构建目录；D 盘还可能是未解锁的 BitLocker 卷。
- 没有说明架构（x64/ARM64）、CRT 依赖、DLL 签名、ACL、`ThreadingModel`、CLSID 注册键、卸载/救援流程。
- Windows 11 的 Smart App Control / WDAC / AppLocker 可能阻止未签名 DLL。

**修正方案**：

- 部署到 `C:\Program Files\FamiliarSmartcard\familiar_cred_provider.dll`，ACL 只允许 SYSTEM/Administrators 写。
- 构建目标与 `LogonUI.exe` 架构一致：x64 Windows 用 `x86_64-pc-windows-msvc`；ARM64 用 `aarch64-pc-windows-msvc`。
- 使用静态 CRT（`-C target-feature=+crt-static`），避免锁屏时缺少 VC++ 运行库。
- 保留 `panic=unwind`（不要 `panic=abort`），配合 `catch_unwind`；但不要依赖它捕获 AV。
- 导出 `DllGetClassObject`、`DllCanUnloadNow`；实现 `IClassFactory` 和 DLL 引用计数；`ThreadingModel=Apartment`。
- 注册键：
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`，默认值为显示名。
  - `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`，默认值为 DLL 路径，`ThreadingModel=Apartment`。
  - 32/64 位注册表视图：GUI 若为 32 位，写 `KEY_WOW64_64KEY`；建议全程 64 位。
- 代码签名：至少用受信任的代码签名证书；否则 Smart App Control/WDAC 可能拦截。个人测试可在 VM 中关闭 Smart App Control，但不要在生产机上关闭安全功能。
- 提供 `register.ps1` / `unregister.ps1` / 救援 `.reg`；在 VM 中先测试“CP 崩溃/ DLL 丢失/注册键损坏”时的原生密码登录路径。
- 保留原生密码 CP；不要设置默认 CP、不要自动登录；`pbAutoLogon`/`pbAutoLogonWithDefault` 永远 FALSE。
- 文档写明：Safe Mode / WinRE 下如何删除注册键；准备第二个管理员账户作为救援。

**测试**：

- 在 VM 快照中注册，锁屏、解锁、注销、重启、RDP。
- 删除 DLL/破坏注册键，确认原生密码仍可登录。
- 用 `signtool` 验证签名；用 `Process Monitor` 检查加载路径。

---

## 4. P2 中优先级问题

### P2-1：PIV/OpenPGP 协议细节混在一起，APDU 与返回语义需要分开写

**问题**：

- 计划写“PIV 9D 槽位 / OpenPGP Decryption 槽位”自动探测，但两者的 PIN 命令、解密命令、返回语义不同；登录时自动探测可能选错应用，增加状态和攻击面。
- PIV 的 `GENERAL AUTHENTICATE` ECDH 使用 `7C` 外层、请求 `85`、响应 `82`；不是“直接发临时公钥”。
- OpenPGP 的 `PSO:DECIPHER` 返回的是**会话密钥**，不是裸共享密钥；RSA 版本是 PKCS#1 v1.5，有 padding oracle。
- PIV 的 AID 应使用完整 `A0 00 00 03 08 00 00 10 00 01 00`，不要只用前缀。
- PIV PIN 是 6–8 位，VERIFY 时补 `0xFF` 到 8 字节；OpenPGP PW1 是 6–127，VERIFY 模式 `82`。
- PIV 9D 默认 PIN policy 是 ONCE；OpenPGP PW1 会话在解密后仍可能有效。

**修正方案**：

- **登录时不要自动探测**；注册时确定 `AppType + Slot + Alg + KeyFingerprint`，存进 vault；登录时按记录选择，找不到就失败。
- 为每种协议实现独立的 `CardDecryptor` trait：
  - `PivEcdhP256`
  - `PivEcdhP384`
  - `PivEcdhX25519`（如使用 Yubico 扩展）
  - `OpenPgpEcdh`
  - `OpenPgpRsa`（不推荐）
- APDU 表写进文档和测试：

```text
PIV SELECT:
  00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00
PIV VERIFY:
  00 20 00 80 08 <PIN padded to 8 bytes with 0xFF>
PIV GENERAL AUTHENTICATE (ECDH P-256):
  00 87 11 9D <Lc> 7C <L> 85 <L> <ephemeral_public_key>
  Response: 7C <L> 82 <L> <shared_secret>
OpenPGP SELECT:
  00 A4 04 00 06 D2 76 00 01 24 01
OpenPGP VERIFY PW1:
  00 20 00 82 <Lc> <PIN>
OpenPGP PSO:DECIPHER:
  00 2A 80 86 <Lc> <ECDH ciphertext>
```

- 处理 `61xx` / `6Cxx`（GET RESPONSE / 重发），处理 `63 Cx`（PIN 错误，剩余次数）、`69 83`（PIN 锁定）、`69 82`（安全状态不满足）、`6A 88`（引用数据不存在）。
- 如果使用 OpenPGP：
  - 解密后显式 `SELECT` 另一个应用（PIV/OATH）结束 PW1 会话，或改用 PIV ALWAYS。
  - 如果启用了 KDF-DO，必须先按卡片 salts 哈希 PIN；否则 VERIFY 会失败。建议关闭 KDF，或在 CP 中实现。
  - `forcesig` 只影响签名，不要误以为它能限制解密。
- **推荐默认：PIV 9D ECDH P-256，PIN policy ALWAYS，专用槽位，on-card generation，attestation。** 这样 PIN 每次操作都被消费，reset 语义更清晰。

---

### P2-2：Vault 格式、AAD、填充、解析器和写入原子性需要定案

**问题**：

- 计划只写了 `[Version | CardSerial/KeyFingerprint | AlgID | Wrapped_DEK | Nonce | Ciphertext | AuthTag]`，没有定义编码、长度、AAD、版本兼容、解析限制。
- AAD 只用 `UserSID` 不够；应绑定用户名、计算机名、卡指纹、app/slot/alg、版本、密码最后修改时间，防止跨用户/跨卡/跨机器替换。
- 密码是 UTF-16LE，密文长度会泄露密码长度；建议固定填充。
- vault 由管理员写入，CP 以 SYSTEM 解析；如果解析器有 bug，可能影响 LogonUI。需要严格长度检查和 fuzzing。
- 注册表写入不是天然原子；写到一半崩溃可能留下损坏的 vault。

**修正方案**：

- 定义带版本的结构（固定字段 + 显式长度），例如：

```text
VaultBlob = DPAPI_MACHINE(
  version: u8
  app: enum { Piv, OpenPgp }
  slot: u8
  alg: enum { P256, P384, X25519, Rsa2048, ... }
  card_pub_fingerprint: [u8; 32]
  eph_pub_enroll: [u8; 65]  // 未压缩 P-256；X25519 为 32
  wrapped_dek: Vec<u8>
  salt: [u8; 32]
  nonce: [u8; 12]
  ciphertext: Vec<u8>       // 固定长度填充后的密码
  tag: [u8; 16]
  password_last_set: u64
  created_at: u64
)
```

- AAD = `version || SID || username || computer_name || app || slot || alg || card_pub_fingerprint || password_last_set`。
- 密码明文先编码为 UTF-16LE，加长度前缀，填充到固定长度（如 256 字节）再加密；不要用密码长度决定密文长度。
- 使用随机 `salt` + HKDF-SHA256 派生 KEK；HKDF `info` 使用域名分隔字符串（如 `FamiliarSmartcard/v1/wrap`）。
- 解析器：固定偏移、长度上限、拒绝未知版本/算法；不要递归；使用 `serde` + `postcard` 或手写固定格式；对解析做 `cargo-fuzz`。
- 写入：先写 `VaultBlob.new`，读回并自检，再写 `VaultBlob`，保留 `VaultBlob.bak`；CP 在主 blob 损坏时可尝试 `.bak`。
- 注册表 ACL：`HKLM\SOFTWARE\FamiliarSmartcard` 仅 SYSTEM/Administrators 完全控制；普通用户只读或不可读。使用 64 位视图。
- DPAPI：`CryptProtectData(..., CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, ...)`；CP 用 `CryptUnprotectData` 同样带 `UI_FORBIDDEN`。明确 DPAPI 机器范围对本地管理员/离线磁盘不是强边界，内层卡片才是；建议 BitLocker，可选 TPM。

---

### P2-3：测试策略不足以支撑“第 101 次也不出事”的信心

**问题**：

- 计划只有“测 100 次”的直觉，没有故障注入、重放、负向测试、解析 fuzzing、状态机不变量测试。
- 单线程 Typestate 能减少竞态，但不能证明“任何错误路径都不会构造出密码”。
- 没有 mock card，真实卡片测试难以覆盖所有错误分支。

**修正方案**：

1. **抽象 `CardTransport` trait**：生产实现 `PcscTransport`，测试实现 `MockTransport`，可注入：
   - 无卡、错卡、卡忙、读卡器消失；
   - VERIFY 返回 `63 Cx` / `69 83`；
   - ECDH 返回错误共享密钥、截断响应、超长响应、`61xx`/`6Cxx`；
   - 解密中途拔卡、RDP 断线。
2. **故障注入测试**：在 Stage 1–7 的每一步注入 `Err`/panic，断言：
   - 不构造 `Stage5/Stage6`；
   - 不返回 `CPGSR_RETURN_CREDENTIAL_FINISHED`；
   - 敏感缓冲区被清零（可用测试探针）。
3. **重放测试**：mock 记录上一次 `S_enroll`，下一次返回旧值，必须失败。
4. **“仅 vault”测试**：只有注册表和 DPAPI 权限，没有卡片，必须无法解密。
5. **解析 fuzzing**：`cargo-fuzz` 跑 vault 解析、APDU 响应解析、KERB 打包/解包。
6. **属性测试**：任意阶段失败，最终状态必须是 `Err`；任意成功，必须经过 `FreshnessProven` 和 GCM tag 校验。
7. **真实硬件测试**：PIV/OpenPGP 各一遍；reset 后直接私钥操作必须 `6982`；PIN 错误/锁定；touch 超时。
8. **VM 集成测试**：注册/卸载/救援；本地锁屏/RDP/NLA；原生密码回退；DLL 丢失；注册键损坏。
9. **静态检查**：`cargo clippy -- -D warnings`、`cargo fmt --check`、`cargo audit`、`cargo deny`；核心 crate 可 `#![forbid(unsafe_code)]`，FFI 隔离。
10. **覆盖率**：用 `cargo llvm-cov` 检查错误分支覆盖，不要只看行覆盖率。

---

### P2-4：构建/依赖/FFI 细节未定，Rust 写 COM 有几个坑

**问题**：

- `windows` crate 的 CP 接口在 `windows::Win32::UI::Shell`，需要正确的 feature；`#[implement]` 生成 COM vtable，但方法签名/输出指针/`HRESULT` 映射需要小心。
- `cdylib` 需要导出 `DllGetClassObject`/`DllCanUnloadNow`；Rust 2024 用 `#[unsafe(no_mangle)]`，2021 用 `#[no_mangle]`。
- `#[implement]` 的方法通常是 `&self`；需要 `RefCell`/`Mutex`，不能假设“对象完全不可变”。
- `panic=abort` 会让 `catch_unwind` 失效；DLL 必须 `panic=unwind`。
- 动态 CRT 在锁屏环境可能缺少依赖；静态 CRT 更稳。
- `rsa` crate 有已知 Marvin 时序侧信道 advisory（RUSTSEC-2023-0071）；如果只用 ECDH，可以不引入。

**修正方案**：

- 固定 `rust-toolchain.toml`；锁定 `windows`/`windows-core` 版本；启用 `Win32_UI_Shell`、`Win32_Security_Authentication_Identity`、`Win32_Devices_SmartCards`、`Win32_Security_Cryptography`、`Win32_System_Registry`、`Win32_System_Com` 等 feature。
- `cred-provider`：`crate-type = ["cdylib"]`；`panic = "unwind"`；`+crt-static`；导出 `DllGetClassObject`、`DllCanUnloadNow`；实现 `IClassFactory` 和引用计数。
- `scard-core`：`rlib`；`#![forbid(unsafe_code)]`，PC/SC FFI 单独模块并加 `#![deny(unsafe_op_in_unsafe_fn)]`。
- 依赖建议：`windows`、`zeroize`、`aes-gcm`、`p256`、`x25519-dalek`（如用 X25519）、`hkdf`、`sha2`、`subtle`、`rand`/`getrandom`、`thiserror`；避免不必要的 GUI/网络依赖。
- `cargo deny` 配许可证/ advisory；`cargo audit` 进 CI。
- 给 CP 写一个最小的 COM 测试宿主（或使用 `rundll32`/自定义 `CoCreateInstance` 测试），至少验证 `DllGetClassObject` 和 `IClassFactory`。

---

## 5. 修正后的推荐架构

### 5.1 修正后的 Typestate

```text
AuthPipeline
  -> VaultLoaded          // DPAPI 解开外层，解析并校验版本/AAD 元数据
  -> CardConnected        // PC/SC context + transaction + 匹配卡指纹
  -> PinVerified          // VERIFY PIN；PIN 立即清零
  -> FreshnessProven      // 新鲜 ECDH 挑战；防重放/假卡
  -> KeyUnwrapped         // 静态 Eph_Pub_enroll + 卡片 ECDH -> KEK -> 解封 DEK
  -> CredentialDecrypted  // AES-256-GCM 解出密码；DEK 清零
  -> KerbPacked           // CredProtectW + KERB_INTERACTIVE_UNLOCK_LOGON
```

每一步仍然按值消费 `self`；`FreshnessProven` 是新增的强制关卡，任何跳过都会在编译期无法构造 `KeyUnwrapped`。

### 5.2 修正后的登录流程（PIV 9D ECDH P-256）

```text
1. 读取 HKLM\SOFTWARE\FamiliarSmartcard\Users\<SID>\VaultBlob
   DPAPI 解开外层；校验 version / SID / username / computer / fingerprint
2. SCardEstablishContext(SCARD_SCOPE_USER)
   SCardListReadersW -> 按 fingerprint 找匹配读卡器
   SCardConnectW(SCARD_SHARE_SHARED, T0|T1)
   SCardBeginTransaction
3. SELECT PIV AID
   GET DATA / certificate -> 校验 card_pub_fingerprint
4. VERIFY PIN (00 20 00 80 08 <padded PIN>)
   立即 zeroize PIN
5. FreshnessProven:
   生成新的 P-256 临时密钥对
   GENERAL AUTHENTICATE(00 87 11 9D ... 7C ... 85 ...)
   比较 expected = ECDH(eph_priv_fresh, card_pub) 与卡片返回
   不匹配 -> 失败
6. KeyUnwrapped:
   GENERAL AUTHENTICATE(..., Eph_Pub_enroll)
   HKDF(shared_secret, salt, info) -> KEK
   AES-256-GCM open(Wrapped_DEK) -> DEK
7. CredentialDecrypted:
   AES-256-GCM open(DEK, nonce, ciphertext, AAD) -> UTF-16LE 密码
8. KerbPacked:
   CredProtectW(password) -> protected
   KERB_INTERACTIVE_UNLOCK_LOGON + MessageType
   CoTaskMemAlloc 序列化
9. SCardEndTransaction(SCARD_RESET_CARD)
   SCardDisconnect(SCARD_RESET_CARD)
   SCardReleaseContext
```

### 5.3 OpenPGP 备选

如果坚持 OpenPGP：

- 使用 OpenPGP DEC 槽位 + ECDH（X25519 或 P-256），不要用 RSA。
- 新鲜性挑战：生成一个含随机会话密钥的 ECDH 密文，`PSO:DECIPHER` 返回会话密钥，与期望值比较；通过后再发送静态密文解出 DEK。
- 解密完成后 `SELECT` PIV/OATH AID 结束 PW1 会话，再 reset。
- 如果启用了 KDF-DO，CP 必须实现 PIN 哈希；否则关闭 KDF。
- UIF/touch 要考虑 RDP 场景下的提示；如果开启，`GetSerialization` 会等待触摸。

### 5.4 客户端侧 CP（可选，保留 NLA）

如果未来要求 NLA 必须开启，或远程主机不可信：

- 在**客户端**实现 `CPUS_CREDUI` Credential Provider；
- 客户端用本地 RS-Key 解密目标账户密码，返回给 CredSSP；
- 服务端不需要 FamiliarSmartcard；NLA 保持开启；PIN 不经过远程主机；
- 代价：vault 在客户端；远程主机仍会收到密码（CredSSP 的固有属性）；需要单独设计客户端部署。

---

## 6. 实施顺序建议

1. **Phase 0：定案与硬件准备**
   - 决定 PIV vs OpenPGP（建议 PIV 9D P-256 ALWAYS）。
   - 决定远程 CP vs 客户端 CP（建议先做远程 CP，VM 测试）。
   - 决定本地账户策略（随机密码 + 备份 + 永不过期）。
   - 烧 OTP、secure boot、改 PIN/PUK/mgmt key、on-card 生成密钥、attestation。
   - 准备 VM 快照、第二个管理员账户、救援脚本。
2. **Phase 1：`scard-core` + mock transport**
   - Typestate（含 FreshnessProven）。
   - 密码学（HKDF/AES-GCM/ECDH；`Eph_Priv` 不落盘）。
   - 故障注入/属性测试/fuzzing。
3. **Phase 2：真实 PC/SC**
   - 事务、reset、PIN 策略、PIV/OpenPGP APDU。
   - Reset 后私钥操作必须 `6982`。
4. **Phase 3：`enroll-gui`**
   - WTS 获取交互式用户/SID；随机密码；`LogonUserW` 一次；vault 原子写入；自检。
5. **Phase 4：`cred-provider`**
   - COM 接口、KERB、CredProtect、ReportResult、零化、错误映射。
   - 注册/卸载/救援；VM 锁屏测试。
6. **Phase 5：RDP/负向测试/加固**
   - NLA 开关、智能卡重定向、断线、拔卡、错卡、PIN 锁定、密码变更。
   - 签名、ACL、文档、威胁模型。

---

## 7. 需要你确认的决策

1. **PIV 还是 OpenPGP？** 建议 **PIV 9D ECDH P-256，PIN policy ALWAYS**，因为 PIN 每次操作被消费、reset 语义清晰；OpenPGP 的 PW1 会话更持久，但 provisioning 更容易（gpg）。
2. **远程 CP 还是客户端 CP？** 你的原始目标是远程锁屏，建议先做远程 CP + NLA 关闭；如果 NLA 必须保留，改客户端 `CPUS_CREDUI`。
3. **本地账户还是 Microsoft 账户？** 建议本地账户；Microsoft 账户的密码生命周期不可控，vault 容易过期。
4. **RP2350 还是认证硬件？** RP2350 用于开发/个人实验；高价值账户建议 YubiKey 5 / 认证 PIV 卡。无论哪种，都要烧 OTP、secure boot、改默认 PIN/PUK/mgmt key。
5. **GUI 框架？** 建议原生 Win32 最小界面；如果坚持 egui，需要额外的密码缓冲清零验证。
6. **是否接受“远程主机可见 PIN/密码”？** 远程 CP 方案固有；如果不接受，只能走客户端 CP 或原生智能卡 PKINIT（需要 PKI/域，复杂度高）。

---

## 8. 总体评价

你的直觉——**单线程、Typestate、密码学绑定、fail-fast、保留原生密码回退**——是正确的高保障工程方向。当前计划的主要问题不是“思路错”，而是：

- 密码学协议缺少**新鲜性**，会被重放；
- 关键持久化不变量（`Eph_Priv` 不落盘）没有写明；
- Windows CP 的实际接口细节（KERB、CredProtect、事务、COM 状态）与示例有偏差；
- RS-Key 的硬件安全前提（OTP burn、无 secure element、未审计）没有进入威胁模型；
- 密码生命周期、RDP/NLA、部署与救援这些“工程现实”还没有设计。

**建议先把本报告的 P0/P1 修进计划，再开始写代码。** 修正后的架构仍然保持你想要的“没有真实密钥就绝对解不开密码”的属性，而且比当前版本更接近可验证、可测试、可救援的状态。
