# Familiar Smartcard 使用与运维手册

> **重要安全前提**：
> - 支持符合 **NIST SP 800-73-4 标准 PIV 协议** 的智能卡与硬件安全密钥（如 YubiKey、JavaCard PIV、开源 PIV 硬件密钥等）。当卡片支持 `00 F7` 元数据扩展时，程序会强制要求 `0x9D` 槽位为**卡内生成（On-card）**的 **ECC P-256** 密钥且 **`PIN policy = ALWAYS`**（`ONCE`、`NEVER` 或外部导入私钥会被硬性拒绝）；对不含私有扩展的标准 PIV 卡则兼容读取 `5F C1 0B` 标准证书公钥。
> - 正式投入使用前，请务必修改卡片出厂默认的 PIV PIN（`123456`）、PUK（`12345678`）与 Management Key，并完成硬件自身的防篡改固化。
> - 开启账户锁定策略（管理员运行 `net accounts /lockoutthreshold:5`），且在关闭 RDP NLA 时**只允许通过 WireGuard / Tailscale / IPsec 访问 3389 端口**。

所有运行时 UI、命令行与锁屏提示均为英文（遵循 `PROJECT_PRINCIPLES.md`）；本文档为中文操作说明。

---

## 0. 发布包组成与安装目录

编译构建（`cargo build --release --workspace`）后，完整组件包含以下三个二进制文件（以及可选救援脚本）：

```text
familiar-enroll.exe          # 图形化注册/轮换密码/PIN解锁与PUK管理/自检/内联安装与 CLI 工具
cred_provider.dll            # Windows Credential Provider V2 外壳
familiar-auth-helper.exe     # 同会话隔离 PC/SC 解锁子进程（防 LogonUI 卡死）
register_cp.ps1              # 备用命令行注册脚本（GUI 已内置纯 Rust 安装器，无需依赖此脚本）
unregister_cp.ps1            # 紧急注销脚本
rescue_delete_cp.reg         # WinRE / 安全模式救援注册表文件
```

安装后程序会自动将受保护文件部署至 `C:\Program Files\FamiliarSmartcard\`，并将敏感配置注册表 `HKLM\SOFTWARE\FamiliarSmartcard` 的 ACL 锁定为仅 `SYSTEM` 和 `Administrators` 完全控制。

---

## 1. 先决条件检查

1. **智能卡服务**：插卡客户端与目标主机（或 VM）的 `SCardSvr` 服务均处于运行状态：
   ```powershell
   Set-Service SCardSvr -StartupType Automatic
   Start-Service SCardSvr
   ```
2. **账户类型**：目标账户必须是独立的 **Windows 本地账户（Workgroup）**，不支持 AD 域账户或 Microsoft 云账户。
3. **账户锁定策略（强烈建议）**：防止攻击者绕过智能卡直接爆破旁边的原生密码框：
   ```powershell
   net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
   ```
4. **验证读卡器、PIN/PUK 状态与卡片策略**：
   ```powershell
   .\familiar-enroll.exe --probe
   ```
   确认输出中 `0x9D` 槽位已就绪（例如支持元数据扩展的卡片显示 `Slot 0x9D: key present [alg=0x11, pin=ALWAYS, touch=NEVER, origin=On-card]`）。

---

## 2. 推荐做法：使用主入口完成安全绑定与随机密码轮换

> **推荐主入口**：**`Set up & rotate password (Recommended)`**  
> 这是生产环境与正式远程主机的标准做法。程序会自动生成 **36 位高熵无歧义随机密码**（9 组 `XXXX-XXXX-...`，约 180 bits 熵，剔除了易混淆的 `0/O/1/I/l`），彻底消除人工弱口令被远程猜解的风险，同时保证**未完成真卡自检与恢复单确认前绝不修改系统密码**。

### 完整操作步骤

1. 双击运行 `familiar-enroll.exe`（自动请求 UAC 管理员权限，后台探测 PIV 智能卡）。
2. 在主窗口填写：
   - **`PIV PIN (6-8 digits)`**：输入当前智能卡的 PIV PIN。
   - **`Current Windows password`**：输入目标本地账户**当前的** Windows 密码。
3. 点击主按钮 **`Set up & rotate password (Recommended)`**：
   - **第 1 阶段（零风险预检与真卡自检）**：程序自动检验内置安装包完整性、识别当前交互式会话用户、验证当前密码、校验卡片 `0x9D` 槽位策略及可选的 `0xF9` 证明链（首次绑定自动固定根指纹），随后用候选 36 位随机密码在真卡上跑完一次完整的两轮 PIN + 双重 ECDH 解密自检。*若此阶段任何一步失败，系统原密码毫发无损。*
4. **第 2 阶段（离线恢复单抄写/打印与末 6 位核验）**：
   - 自检通过后，弹出模态窗口 **`Step 2 of 2: Verify Offline Recovery Sheet`**。
   - **离线记录恢复密码**：使用纸笔完整抄写框内显示的 `XXXX-XXXX-...` 36 位恢复密码（或点击 `Print recovery sheet...` 直接输出到物理打印机；**严禁选择 PDF 虚拟打印机或拍照存盘**）。
   - **重要提示**：使用 Windows 原生密码框应急登录时，**必须连同中间的连字符 `-` 一起原样输入**！
   - 在下方输入框中手动输入恢复密码的**最后 6 位字符**，勾选确认框，点击 **`Confirm & Rotate Windows Password`**。
5. **第 3 阶段（前置安装与原子生效）**：
   - 程序**先部署并注册 Credential Provider 与隔离辅助进程**（若部署失败绝不改密），随后备份旧凭据、通过 `NetUserSetInfo` 将本地账户切换为 36 位恢复密码并开启“密码永不过期（`UF_DONT_EXPIRE_PASSWD`）”、写入并读回校验新 `VaultBlob`。
   - 状态栏提示 `Setup complete. Lock the screen and sign in with Familiar Smartcard.` 即告完成。

---

## 3. 关于辅助入口 `Re-bind current password (Dev / Rescue)` 的风险说明（不推荐）

窗口保留了次级按钮 **`Re-bind current password (Dev / Rescue)`**，该入口**不修改系统密码**，直接将当前输入的密码加密进 Vault。

### 为什么正式环境强烈不推荐使用该入口？

1. **原生密码通道成为短板（绕过智能卡爆破风险）**：为了防止用户永久锁死，Windows 原生密码 Provider 始终并存。在 RDP 关闭 NLA（`UserAuthentication = 0`）的场景下，攻击者连接 3389 后可直接点击“登录选项（Sign-in options）”切回普通密码框。如果账户仍保留人类易记的短密码/常用密码，攻击者无需接触你的智能卡即可尝试口令猜解。
2. **密码过期与生命周期漂移**：未经过主流程轮换的普通账户可能未开启 `UF_DONT_EXPIRE_PASSWD`，一旦系统策略触发密码过期或用户随手改密，Vault 会因时间戳/密码不一致立即失效。

### 仅限以下两种场景使用该辅助入口

- **隔离开发/测试虚拟机（VM）**：在封闭测试网中希望保留固定测试口令快速调试。
- **应急救援后重新绑卡**：例如更换了新的 PIV 智能卡，但当前系统密码已经是之前生成的 36 位高强度恢复密码，且不想重新抄写一份新的恢复单时，可凭恢复单密码进入桌面后先执行 `Re-pin card root`，再用该恢复密码执行 `Re-bind current password`。

---

## 4. 卡片 `0xF9` Attestation 根证书固定与重置（CLI 与 GUI 方法）

当 PIV 智能卡支持 `00 F9` 证明扩展时，程序会在首次注册时验证 `0x9D` 证明证书是否由卡内 `0xF9` 证明根签发，并将 `0xF9` 公钥 SHA-256 指纹固定在受保护注册表 `HKLM\SOFTWARE\FamiliarSmartcard\Attestation\PinnedF9Fingerprint` 中，防止伪造卡片替换。

当更换了新的物理智能卡、执行了卡片 PIV 出厂重置、或硬件安全密钥重新生成了设备级证明根时，**必须先执行重新固定（Re-pin）再重新绑定账户**：

### 方法一：GUI 图形界面重置固定（推荐交互式使用）

1. 插入新的（或已重置的）PIV 智能卡，确保 `0x9D` 槽位密钥已就绪。
2. 打开 `familiar-enroll.exe`，点击第二排的 **`Re-pin card root`** 按钮。
3. 在弹出的确认对话框中点击 **Yes**，程序会校验新卡的 `0x9D`/`0xF9` 签名链并将新的 `0xF9` 指纹写入 `HKLM`。
4. 随后点击 `Set up & rotate password (Recommended)`（或 `Re-bind current password`）更新账户 Vault。

### 方法二：CLI 命令行重置或清除（适合脚本/远程终端维护）

在**管理员 PowerShell / CMD** 中执行：

```powershell
# 查看当前机器固定的 0xF9 根指纹以及读卡器中卡片的匹配状态
.\familiar-enroll.exe --probe

# 直接验证当前插入的 PIV 智能卡并将它的 0xF9 根更新固定到 HKLM
.\familiar-enroll.exe --repin-attestation

# 或者仅清除 HKLM 中已固定的旧 0xF9 指纹（下次注册时自动固定新卡）
.\familiar-enroll.exe --clear-attestation
```

---

## 5. 本地锁屏与 RDP 远程访问使用指南

### 5.1 本地锁屏解锁
按 `Win + L`，在当前已绑卡账户下会自动显示 `Sign in with Familiar Smartcard`（未绑卡的本地账户不会显示多余的智能卡磁贴），输入 6~8 位 PIV PIN 回车即可。

### 5.2 RDP 远程锁屏访问（含“Other user / 其他用户”场景）

1. **服务端配置（仅限 VPN / 受控内网，严禁公网直连 3389）**：
   ```powershell
   Set-ItemProperty `
     -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
     -Name UserAuthentication -Value 0
   ```
2. **客户端 `.rdp` 配置**：
   ```text
   full address:s:<目标主机内网/VPN IP>
   redirectsmartcards:i:1
   enablecredsspsupport:i:0
   authentication level:i:0
   prompt for credentials:i:0
   ```
3. **支持两种远程锁屏形态**：
   - **显示已知用户头像时**：直接选中已绑定账户下的 `Sign in with Familiar Smartcard`，输入 PIN 登录。
   - **开启了“不显示上次登录名”策略或点击左下角 `Other user` 时**：选中 `Sign in with Familiar Smartcard`，依次填入本地用户名（如 `kasumi_virt` 或 `.\kasumi_virt`）与 Familiar Smartcard PIN 即可登录。
4. **防卡死超时保护**：每次认证由同会话隔离进程 `familiar-auth-helper.exe` 执行，默认 10 秒硬超时（Touch 策略卡片为 22 秒）。即使客户端拔卡或网络中断导致智能卡通道挂起，锁屏也会准时中断返回提示，随时可点击“Sign-in options”切回恢复单密码登录。

---

## 6. PIV PIN 防误锁保护、PUK 原地解锁与应急救援流程

### 6.1 最后 1 次机会前的 60 秒防误触冷却保护
标准 PIV 智能卡默认最多允许连续输错 **3 次** PIN。为防止手滑连按回车直接把硬件锁死：
- 前 **2 次** 输错（剩余 2 次 -> 剩余 1 次）后，主机立即为该卡启动 **60 秒强制安全冷却**；
- 冷却期间再次提交不会向卡片发送 `VERIFY PIN`，因此不会消耗最后 1 次宝贵的硬件机会；
- 60 秒结束后放行第 3 次（最后 1 次）尝试；验证成功则卡片自动恢复满额计数。

### 6.2 卡片 PIN 锁死（`6983`）时：使用 PUK 原地救卡（无需重新绑卡！）
无论是 `Set up & rotate` 还是 `Re-bind current password` 模式，PIV 智能卡内部都自带独立的 **PUK 码**（PIV 标准出厂默认为 `12345678`；正式使用前建议通过下方 GUI 或 CLI 修改为你自己的 6–8 位 PUK 并离线抄写保存）。**通过 PUK 重置 PIN 不会改变 `0x9D` 密钥对，原有 Windows Vault 无需重新绑定即可继续使用。**

1. **方法 A：直接在 Windows 锁屏界面原地解锁并登录**
   - 当第 3 次输错触发硬件锁定后，锁屏磁贴会自动展开 **`Unblock Familiar Smartcard with PUK`** 模式（平时也可主动点击磁贴下方的 `PIN blocked? Unblock with PUK` 链接切换）；
   - 填入 **Card PUK**（未改过则为 `12345678`）、**New PIN** 与 **Confirm new PIN** 后回车，即可一次性解锁卡片（恢复 3 次计数）并直接登录进入桌面。
2. **方法 B：通过 `familiar-enroll.exe` 图形界面管理 PIN 解锁与修改 PUK**
   - 打开 `familiar-enroll.exe`，点击第二排的 **`Unblock PIN / PUK...`** 按钮；
   - 上半区可用 PUK 解锁已锁死的 PIN 并恢复 3 次计数；下半区可将出厂默认 PUK（`12345678`）修改为你自己的 6–8 位高强度 PUK。
3. **方法 C：通过 CLI 命令行解锁 PIN 或修改 PUK**
   ```powershell
   # 查看当前卡片 PIN / PUK 剩余次数及是否仍为出厂默认值
   .\familiar-enroll.exe --probe

   # 用 PUK 解锁已锁死的 PIN 并设置新 PIN（恢复 3 次机会）
   .\familiar-enroll.exe --unblock-pin <PUK> <NEW-PIN>

   # 修改卡片 PUK（将默认 12345678 改为自定义 6-8 位 PUK）
   .\familiar-enroll.exe --change-puk <CURRENT-PUK> <NEW-PUK>
   ```

### 6.3 系统应急救援流程（未带卡或卡片损坏）

1. **首选救援**：在锁屏点击“登录选项（Sign-in options）”，切换回 Windows 原生密码图标，输入纸质恢复单上的 36 位随机密码（**包含连字符 `-`**；若为 `Re-bind` 模式则输入原本的 Windows 密码）进入桌面。
2. **注销自定义 Credential Provider**：
   进入桌面后在管理员 PowerShell 运行：
   ```powershell
   .\scripts\unregister_cp.ps1
   ```
   或在安全模式 / WinRE 下导入 `rescue_delete_cp.reg`（删除 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}`）。
