# FamiliarSmartcard 使用说明（开发/VM 测试）

> 当前卡片：RS-Key PIV 9D，P-256，`PIN policy = ALWAYS`，`touch = NEVER`。  
> 开发 PIN：`123456`；默认 management key 未改。**仅用于开发测试，正式使用前必须改 PIN/PUK/management key。**

所有 UI 文案均为英文；本文是操作说明。

---

## 0. 先决条件

- 本机（插卡机）与 VM 的 `Smart Card` 服务（`SCardSvr`）都在运行。
- 本机与 VM 都是 Windows Pro/Enterprise（VM 作为 RDP 服务端）。
- VM 账户：`kasumi_virt`，密码：`123456`（当前测试密码）。
- 本机与 VM 在同一网络，VM IP：`192.168.51.3`。
- VM 上保留 Windows 原生密码登录，不要禁用。

检查服务（本机和 VM 的管理员 PowerShell）：

```powershell
Get-Service SCardSvr
Start-Service SCardSvr
Set-Service SCardSvr -StartupType Automatic
```

---

## 1. 把发布包复制到 VM

发布包在本机：

```text
D:\Projects\FamiliarSmartcard\dist\FamiliarSmartcard\
```

推荐用 RDP 的“驱动器重定向”把本机 `C:` 或项目盘映射到 VM。连接时在
`mstsc -> 本地资源 -> 详细信息` 勾选：

- `智能卡 (Smart cards)`
- 需要复制文件时再勾选 `驱动器`

VM 内通常可以通过 `\\tsclient\D\Projects\FamiliarSmartcard\dist\FamiliarSmartcard`
访问发布包。把它复制到 VM 的：

```text
C:\FamiliarSmartcard\
```

发布包内容：

```text
familiar-enroll.exe
cred_provider.dll
register_cp.ps1
unregister_cp.ps1
rescue_delete_cp.reg
USAGE.md
```

---

## 2. 在 VM 中验证智能卡重定向

VM 内打开 PowerShell：

```powershell
cd C:\FamiliarSmartcard
.\familiar-enroll.exe --probe
```

期望输出包含：

```text
Reader: RS-Key RS-Key Security Key 0
PIV: selected, card: RS-Key PIV
Slot 0x9D: key present
```

如果看不到读卡器：

1. 确认本机 `SCardSvr` 正在运行。
2. 确认 `mstsc` 勾选了“智能卡”。
3. 确认 VM 的 `SCardSvr` 正在运行。
4. 确认组策略没有禁止“智能卡设备重定向”。
5. 重新插拔 RS-Key，再运行 `--probe`。

---

## 3. 绑定 VM 的 `kasumi_virt` 账户

VM 内直接双击：

```text
C:\FamiliarSmartcard\familiar-enroll.exe
```

程序会自动弹出 UAC 请求管理员权限；同意后窗口打开。窗口启动时会**自动探测**
RS-Key，状态栏应显示：

```text
RS-Key detected. PIV 9D key is ready.
```

在 GUI 中填写：

- `PIV PIN (6-8 digits)`：`123456`
- `Windows password`：`123456`（VM 账户当前密码）

点击主按钮：

1. `Set up this account`

它会一气呵成执行：

- 再次检测 RS-Key / 9D 密钥
- 通过 WTS 识别当前交互式账户
- 用 `LogonUserW` 验证 Windows 密码
- 计算 `password_last_set`
- 生成 vault 并写入 HKLM
- 用 RS-Key 做一次完整解密自检
- 自动调用旁边的 `register_cp.ps1` 注册 Credential Provider

期望状态：

```text
Setup complete. Lock the screen and sign in with RS-Key.
```

输出框会显示账户、SID、卡名、指纹、自检结果和注册结果。

需要单独操作时，窗口里也有：

- `Probe card`
- `Self-test`
- `Register provider`
- `Clear output`

> GUI 用 WTS 识别**交互式会话用户**，不是提权后的管理员账户。  
> 如果 `Windows password validation failed`，说明账户类型/密码不匹配；不要继续绑定。

---

## 4. 注册 Credential Provider

`Set up this account` 成功后会**自动注册**。如果跳过或失败，可以点 GUI 的
`Register provider`，或管理员 PowerShell：

```powershell
cd C:\FamiliarSmartcard
.\register_cp.ps1
```

脚本会：

- 把 DLL 复制到 `C:\Program Files\FamiliarSmartcard\familiar_cred_provider.dll`
- 注册 CLSID `{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}`
- 设置 `ThreadingModel=Apartment`
- 设置 vault 注册表 ACL 为 SYSTEM/Administrators

注册后不要重启到“只剩自定义 CP”的状态；原生密码 CP 仍然保留。

---

## 5. 测试本地锁屏解锁

VM 内按 `Win + L`：

1. 选择 `Sign in with RS-Key`
2. 输入 PIN `123456`
3. 解锁

如果失败：

- 点击“登录选项/其他用户”，切回原生密码。
- 检查 `C:\FamiliarSmartcard\familiar-enroll.exe --probe` 是否仍能看到卡。
- 检查 vault 是否存在：GUI 的 `Self-test`。
- 不要反复输错 PIN；PIN 只有 3 次。

---

## 6. 测试 RDP 远程锁屏

> 自定义 Credential Provider 在 RDP 下要求**服务端关闭 NLA**。  
> 如果 NLA 开启，远程连接会先在客户端完成认证，不会显示远程锁屏的自定义 CP。

### 6.1 VM 关闭 NLA（仅测试网络）

VM 内管理员 PowerShell：

```powershell
Set-ItemProperty `
  -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name UserAuthentication -Value 0
```

确认 VM 的 `SCardSvr` 正在运行。

> 3389 只能暴露在受信任的 VM 网络/VPN 内，不要直接暴露公网。

### 6.2 本机连接 VM

本机创建/编辑 `.rdp`：

```text
full address:s:192.168.51.3
username:s:kasumi_virt
redirectsmartcards:i:1
enablecredsspsupport:i:0
authentication level:i:0
prompt for credentials:i:0
```

连接后：

1. 客户端可能出现凭据提示，可输入占位用户名或直接继续。
2. 远程显示 VM 的锁屏界面。
3. 选择 `Sign in with RS-Key`。
4. 输入 PIN `123456`。
5. 远程锁屏通过 RDP 智能卡重定向访问本机的 RS-Key，完成 ECDH 并登录。

如果连接后直接进入桌面，说明 NLA 没有关闭，或连接用了缓存的 CredSSP；删除/重建
`.rdp`，确认 `enablecredsspsupport:i:0`。

---

## 7. 救援

如果自定义 CP 出问题：

1. 锁屏点击“登录选项”，切回原生密码；这是第一救援通道。
2. 如果 CP 崩溃或 DLL 丢失，原生密码仍应可用。
3. 进入桌面后管理员 PowerShell：

```powershell
cd C:\FamiliarSmartcard
.\unregister_cp.ps1
```

或双击/导入：

```text
rescue_delete_cp.reg
```

4. Safe Mode / WinRE 下也可以删除
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}`。

如果 PIN 被锁：

```powershell
# 仅是开发卡示例；PUK 默认 12345678
& 'C:\Program Files\Yubico\Yubico PIV Tool\bin\yubico-piv-tool.exe' `
  -r 'RS-Key' -a unblock-pin -P 12345678 -N 123456
```

---

## 8. 当前限制（必须知道）

- 当前 GUI 绑定的是**现有 Windows 密码**；随机密码两阶段轮换尚未接入。
- 当前 9D 使用默认 PIN/management key，仅开发使用；正式前必须修改，且**禁止**
  `yubico-piv-tool` / `ykman` 的 `--protect`（它会把 management key 托管在 PIN 下）。
- 正式卡还需要 OTP burn、`rsk otp lock-page58`、`scripts/pt.sh`、Secure Boot、
  `f9` attestation pinning。
- Credential Provider 目前直接同步执行 PC/SC；helper 进程/硬超时仍在计划中。
- RDP 远程锁屏方案中 PIN 会到达 VM；VM 必须可信。

---

## 9. 常用命令

```powershell
# 只读探测
.\familiar-enroll.exe --probe

# 仅卡片加解密自检（不写注册表、不改 Windows 密码）
.\familiar-enroll.exe --card-selftest 123456

# 启动 GUI（管理员）
Start-Process .\familiar-enroll.exe -Verb RunAs

# 注册/注销 CP
.\register_cp.ps1
.\unregister_cp.ps1
```
