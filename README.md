# nas — 极简 Samba / iSCSI 管理

一个单文件、纯交互式的 Samba 管理工具。只依赖 Python 3 标准库，不需要 Web 服务、数据库或后台进程。

```
/usr/local/bin/nas
/usr/local/share/doc/nas/README.md
```

## 功能

| 模块 | 内容 |
|---|---|
| 共享 | 新建、编辑（名称/路径/说明/只读/可见/来宾/可见用户）、删除、表格详情 |
| 权限 | 查看、设置（用户/组 rwx）、重置（多选收回 + 可选重置属主/基础权限） |
| 用户 | 查看、添加、重置密码、启用/禁用、删除（可同时删除 Linux 用户） |
| iSCSI | 新建/删除 iSCSI 磁盘、ZFS zvol、initiator ACL、CHAP、Portal |
| ZFS | 存储池状态、scrub、数据集/zvol 创建删除、快照创建/回滚/删除、加密数据集密钥管理 |
| 自动快照 | 每个数据集可单独设置计划，按计划创建 ZFS 快照并清理超过保留份数的旧快照 |
| 硬盘 | 磁盘列表、SMART、机械硬盘休眠/状态监控/异常唤醒保护/推送提醒、系统盘/ZFS 池空间监控、创建/导入 ZFS 池 |
| 加密联动 | 未解锁时访问被拒绝、停止导出 iSCSI LUN；解锁后自动挂载/恢复 |
| 依赖 | 检查 ZFS / SMB / iSCSI / wsdd2，按缺失项安装 |
| 系统集成 | 一键安装依赖、启用服务、安装开机保护、设置 canmount=noauto |
| 网络发现 | 开关 NetBIOS + WS-Discovery（让 NAS 出现在 Windows「网络」） |
| 安全 | 写入前 testparm 校验、自动备份、原子替换、热加载 |

不包含：Web 面板、SMB 会话管理、定时任务。

## 环境要求

```bash
# Debian 需要 contrib 源
apt install python3 \
            zfsutils-linux zfs-dkms linux-headers-$(uname -r) \
            samba acl wsdd2 targetcli-fb e2fsprogs smartmontools hdparm
```

脚本的一键安装会自动给 Debian 源补 `contrib`，并安装 `zfs-dkms` 和当前内核头文件。

`e2fsprogs` 提供 `chattr`，用于锁住未挂载的加密数据集挂载点。

- Debian 12/13，Python 3.10+
- 脚本启动器是 `/bin/sh`，会先检查 Python；没有 Python 时直接提示安装命令，不会只报 `bad interpreter`
- 直接用 `python3 /usr/local/bin/nas` 运行也可以
- 必须以 root 运行；非 root 直接退出
- `wsdd2` 可选，但 Windows 10/11 在「网络」里发现 NAS 需要它

## 运行

```bash
nas
```

必须是真实终端（SSH 或本地控制台），不支持管道/非交互调用。

首次在别的位置运行（例如 `python3 /tmp/nas`）时，root 下会自动复制到 `/usr/local/bin/nas` 并从那里重新执行。

已经安装过时，手动运行一个**版本更高**的脚本会自动覆盖更新 `/usr/local/bin/nas`，然后从新版本重新执行。已安装版本比当前运行版本新时不会降级。

如果设置了 `NAS_NO_SELF_INSTALL=1`，不会自动安装或更新。

启动后是全屏仪表盘：顶部实时显示共享数、用户数、网络发现、硬盘/ZFS/iSCSI 状态，告警行标黄；菜单按「共享与存储 / 硬件 / 系统」分组，右侧方括号是快捷键（`s` SMB、`i` iSCSI、`z` ZFS、`d` 硬盘、`e` 依赖、`c` 系统集成、`q` 退出）。

子菜单、选择框、输入框、多选、确认框都内嵌在同一套界面里；命令输出会在分页视图中滚动查看，不再刷屏。

按键：

```
↑/↓     移动（长列表自动滚动）
Enter   确认
空格    多选时切换勾选
q / Esc 返回上一级
```

## 自动快照

ZFS 管理 → 自动快照，按计划为选中的数据集创建 `auto-YYYYmmdd-HHMMSS` 快照，并按保留份数清理旧的自动快照（只清理 `auto-` 前缀，手动快照不动）。

- 计划：每个数据集各自设置（每小时整点、每 6 小时、每天指定时间、每周指定时间）；每个不同计划生成一个 `nas-auto-snapshot-<hash>.timer`，互不影响
- 新加入的数据集使用默认计划，之后可在「设置各数据集计划」里单独调整
- 保留：每个数据集各自保留最新 N 份，`0` 表示不清理
- 执行：对应的 `nas-auto-snapshot-<hash>.timer` 触发 `/usr/local/bin/nas`（`NAS_AUTO_SNAPSHOT=1`），开机错过的任务会补跑一次
- 手动触发：菜单里「立即执行一次」，或 `NAS_AUTO_SNAPSHOT=1 nas`（定时器单元就是这么调的）
- 状态：配置存于 `/var/lib/nas/auto-snapshot.json`，仪表盘和「系统集成」里能看到定时器状态与上次结果
- 单元文件：`/etc/systemd/system/nas-auto-snapshot-<hash>.service` / `.timer`（按计划去重，改计划时自动重建，旧单元清理）
- 硬盘休眠联动：配置了硬盘休眠时，执行前会用 `hdparm -C` 检查目标池的盘；有盘处于 standby/sleeping 就跳过本次，记入 `pending`，由 `nas-hdd-monitor` 每 60 秒轮询检测到盘唤醒后立即补做（`hdparm -C` 只查电源状态，不会把盘转起来）。补做依赖 `nas-hdd-monitor.service`，它由「系统集成」安装、配置硬盘休眠时一并启用

## 菜单结构

```
nas
├─ SMB 管理
│  ├─ 共享管理
│  │  ├─ ＋ 新建共享
│  │  ├─ <共享名>        ← 进入后上方显示路径/说明/只读/可见性/属主/ACL
│  │  │  ├─ 编辑共享（字段菜单）
│  │  │  ├─ 设置权限
│  │  │  ├─ 重置权限
│  │  │  ├─ 删除共享
│  │  │  └─ 返回
│  │  └─ 返回
│  ├─ 用户管理
│  │  ├─ ＋ 新建用户
│  │  ├─ <用户名>        ← 进入后上方显示 Linux/uid/Samba 状态/SID
│  │  │  ├─ 重置密码
│  │  │  ├─ 启用 / 禁用
│  │  │  ├─ 删除用户
│  │  │  └─ 返回
│  │  └─ 返回
│  ├─ 网络发现管理
│  │  ├─ 开启 / 关闭网络发现
│  │  ├─ 设置网络发现名称
│  │  ├─ 刷新状态
│  │  └─ 返回
│  └─ 返回
├─ iSCSI 管理
│  ├─ ＋ 新建 iSCSI 磁盘
│  ├─ <target IQN>    ← 显示 LUN/Portal/客户端
│  │  ├─ 添加 / 修改客户端
│  │  ├─ 删除客户端
│  │  ├─ 删除 iSCSI 磁盘
│  │  └─ 返回
│  ├─ 启动 / 停止 / 重启服务
│  ├─ 清空所有 iSCSI 磁盘
│  └─ 返回
├─ ZFS 管理
│  ├─ 存储池          ← 容量/健康/碎片，启动 scrub
│  ├─ 数据集          ← 列表、新建数据集、新建 zvol、删除
│  ├─ 快照            ← 列表、创建、回滚、删除
│  ├─ 密钥管理        ← 加密数据集加载/卸载密钥、挂载/卸载
│  └─ 返回
├─ 硬盘管理
│  ├─ 磁盘列表 / SMART  ← 型号/温度/健康/通电时间
│  ├─ 机械硬盘休眠      ← 按盘设置空闲休眠/立即休眠/推送提醒
│  ├─ 创建 ZFS 池       ← stripe/mirror/raidz1/2/3
│  ├─ 导入 ZFS 池       ← 可强制导入
│  └─ 返回
├─ 依赖检查 / 安装
│  ├─ 一键配置本机（安装依赖 + 开机保护）
│  ├─ 安装所有缺失项
│  ├─ 安装 <某个缺失组件>
│  ├─ 刷新状态
│  └─ 返回
├─ 系统集成 / 一键配置
│  ├─ 一键配置本机（含缺失依赖）
│  ├─ 重新应用锁定状态
│  ├─ 刷新状态
│  └─ 返回
└─ 退出
```

## 用户管理

SMB 管理 → 用户管理 提供：

| 操作 | 说明 |
|---|---|
| 查看用户 | 列出 Samba 账户、Linux 账户是否存在、是否禁用 |
| 添加用户 | 输入用户名和密码；Linux 用户不存在时可选择创建（无家目录、nologin） |
| 重置密码 | 选用户，输入两次新密码 |
| 启用 / 禁用 | 切换 `smbpasswd -e` / `-d` |
| 删除用户 | 删除 Samba 账户，可选同时 `userdel` Linux 用户 |

规则：

- 用户名只能包含小写字母、数字、下划线、点和短横线，且以字母或下划线开头
- 密码至少 4 位，输入时不回显
- 创建用户后默认启用
- 删除 Linux 用户前请确认它没有在跑其他服务
- 删除用户后会自动重建所有「仅授权用户可见」共享的共享 ACL，清掉该用户的残留 SID
- 用户建好后，还需要在「设置权限」里给文件系统 ACL 授权，才能访问共享

等价命令：`useradd -M -s /usr/sbin/nologin <name>`、`smbpasswd -a <name>`、`pdbedit -L`。

## 共享可见性

新建和编辑共享时统一用「可见性」字段，三选一：

```
所有人可见
仅授权用户可见（隐藏无权限用户）
对所有人隐藏（只能通过路径访问）
```

对应行为：

| 选项 | smb.conf | 效果 |
|---|---|---|
| 所有人可见 | `browseable = yes` | 所有认证用户都能在列表里看到 |
| 仅授权用户可见 | `browseable = yes` + `access based share enum = yes` + 共享 ACL | 只有共享 ACL 里的用户能看到；其他用户隐藏且连接被拒 |
| 对所有人隐藏 | `browseable = no` | 不出现在任何人的列表里，只能直接输入路径访问 |

选「仅授权用户可见」时会接着问：

```
有没有无权限但需要显示的用户？ [y/N]
```

这些用户只拿到共享级 ACL 的 `READ`：

- 能在共享列表里看到
- 可以连接，但文件系统 ACL 不给他们权限，所以看不到内容

这里**不使用 `valid users`**，因为 Samba 在枚举共享时也会检查它：不在 `valid users` 里的用户会连共享都看不到，即使共享 ACL 给了 READ。因此访问控制拆成两层：

- 共享 ACL：谁能看到、谁能连接
- 文件系统 ACL：连接后能读写什么

"可见但连接被拒"在 Samba 的 ABSE 下做不到，能实现的是"可见、可连接，但内容被文件系统 ACL 拒绝"。

其他规则：

- "有权限"自动读取共享根目录 `getfacl` 的具名用户（不含 root 和数字 UID）
- 共享根目录没有具名用户 ACL 时，无法开启"仅授权用户可见"
- 额外显示的用户需要 Samba 账户
- 修改共享 ACL 后会执行 `systemctl reload smbd`，否则枚举缓存不会刷新
- 额外名单保存在 `/var/lib/nas/visibility.json`（`NAS_STATE_DIR` 可改）
- 改名时共享 ACL 和额外名单一起迁移

## 权限模型

新建共享或重置权限后，统一是下面这套：

```
属主/属组   root:root
目录        2770（rwxrws---，setgid）
文件        0770（rwxrwx---，默认）
其他人      ---
```

`smb.conf` 中对应写入：

```ini
inherit owner     = windows and unix
create mask       = 0770
force create mode = 0110
directory mask    = 0770
```

- `inherit owner`：通过 SMB 新建的文件属主继承目录 → root
- `setgid`（2770 的那一位）：新建内容属组继承目录 → root
- 访问权只来自 POSIX ACL，没列出的用户没有任何权限
- 目录会自动写默认 ACL，新建内容继承同样的权限

### Windows 可执行文件

所有共享默认允许执行，新建文件自动带 `x`，Windows 可以直接运行 `.exe`。

配置固定为：

```ini
create mask       = 0770
force create mode = 0110
directory mask    = 0770
```

原因：

- Windows 客户端创建文件通常请求 `0666`
- `create mask` 只是掩码，不会主动加执行位
- 必须靠 `force create mode` 把 `x` 加回来

已有共享在「系统集成」时会统一更新为这套配置。

已有文件不受新配置影响，需要执行一次：

```text
共享详情 → 修复已有可执行文件权限
```

脚本会给 `.exe/.com/.bat/.cmd/.msi/.scr/.ps1/.vbs` 补执行权限，并保留现有 ACL。

注意：

- 新建的所有普通文件都会带执行位，这是为了兼容 Windows 程序
- 不需要单独的开关

### 查看权限

进入共享后，详情区已经显示属主、权限位、文件系统 ACL 和共享 ACL，不需要单独进入查看。等价于：

```bash
getfacl -p /mnt/...
```

注意：有 ACL 时 `ls -l` 的属组位显示的是 **mask**，以 `getfacl` 为准。

### 设置权限

1. 选类型：用户 / 组
2. 从系统列表选择（列有 Samba 账户或登录 shell 的普通用户，root 不出现；已授权的会显示当前权限）。组列表只显示 Samba 用户的主组，以及有 Samba 用户作为成员的组，不显示纯系统组
3. 空格勾选 读 / 写 / 执行
4. 选择是否递归
5. 确认

等价效果：

```bash
setfacl -R -m u:alice:rwx /mnt/share
setfacl -R -d -m u:alice:rwx /mnt/share
```

目录需要「执行」权限才能进入和遍历子项。

### 重置权限

1. 列出当前有 ACL 的用户/组
2. 空格勾选**要收回**的条目（可多选）
3. 如果共享开启了「仅授权用户可见」，选择收回后仍需保持可见的用户（可空）
4. 选择是否递归
5. 选择是否同时重置属主/基础权限
6. 确认

行为：

- 只删除勾选的条目，**没勾的完全不动**
- 访问 ACL 和默认 ACL 一起删除
- 跳过符号链接，不会因为悬空链接报错
- 不跨子数据集（`find -xdev`）
- 如果勾选重置基础权限：属主改 root、目录 2770、文件 0770，并写回 `inherit owner` 等参数
- 收回后如果还希望该用户"看得见但没权限"，在询问时选中它，会把共享 ACL 降为 `READ` 并保留
- 文件系统 ACL 变化后，共享 ACL 会自动同步：新授权的用户从 `READ` 升到 `FULL`，被收回的用户从共享 ACL 移除

如果只想收回单个用户，就是在这里勾一个，并把"重置基础权限"选否。

## iSCSI 磁盘

使用内核态 LIO，通过 `targetcli` 管理。

### 新建 iSCSI 磁盘

1. 选择已有 ZFS zvol，或「＋ 新建 zvol」（输入父数据集、名称、大小，默认稀疏）
2. 输入 backstore 名称（默认取 zvol 短名）
3. 输入 target IQN（默认 `iqn.YYYY-MM.lan.nas:<名称>`）
4. 输入客户端 initiator IQN
5. 设置 CHAP 用户名和密码（密码回车自动生成）
6. 确认

创建后自动：

```bash
targetcli /backstores/block create name=<名称> dev=/dev/zvol/<数据集>
targetcli /iscsi create <target IQN>
targetcli /iscsi/<target IQN>/tpg1/luns create /backstores/block/<名称>
targetcli /iscsi/<target IQN>/tpg1 set attribute \
    authentication=1 generate_node_acls=0 demo_mode_write_protect=0
targetcli /iscsi/<target IQN>/tpg1/acls create <initiator IQN>
targetcli /iscsi/<target IQN>/tpg1/acls/<initiator IQN> set auth \
    userid=<用户> password=<密码>
targetcli saveconfig
```

- Portal：`0.0.0.0:3260`
- 配置持久化：`/etc/rtslib-fb-target/saveconfig.json`
- 服务：`rtslib-fb-targetctl`

### 客户端连接

Windows iSCSI 发起程序：

```
目标：<NAS-IP>:3260
Target IQN：iqn.YYYY-MM.lan.nas:<名称>
CHAP：勾选，输入用户名和密码
```

Proxmox / Linux `open-iscsi`：

```bash
iscsiadm -m discovery -t sendtargets -p <NAS-IP>
iscsiadm -m node -T <target IQN> -p <NAS-IP> --login
```

### 服务控制

iSCSI 管理菜单里直接提供：

- **启动服务**：`systemctl enable --now rtslib-fb-targetctl`（从 `saveconfig.json` 恢复）
- **停止服务**：`systemctl stop rtslib-fb-targetctl`（`targetctl clear`，断开所有客户端，配置保留）
- **重启服务**：重新加载配置
- **清空所有 iSCSI 磁盘**：删除所有 target 和 backstore 映射，**zvol 和数据保留**，用于从头配置

注意：3260 端口只有在存在 target 时才会监听；服务 active 但没有 target 是正常状态。

### 管理已有磁盘

选中 target 后：

- **添加 / 修改客户端**：输入 initiator IQN + CHAP，重复执行会更新密码
- **删除客户端**：移除 ACL，该客户端立即无法登录
- **删除 iSCSI 磁盘**：删除 target（可选同时删除 backstore 映射，zvol 本身保留）

### 注意

- initiator IQN 必须是客户端真实的 IQN，写错会登录失败（`iscsiadm` 或 Windows 发起程序里可以看到）
- CHAP 密码至少 8 位，创建后会显示一次
- iSCSI 磁盘是块设备，客户端第一次连接后需要自行分区/格式化；NAS 不挂载它
- 同一个 zvol 不要同时被 NAS 本地挂载和 iSCSI 客户端使用
- Portal 监听 `0.0.0.0:3260`，靠 initiator ACL + CHAP 控制访问；需要更严格时可在防火墙限制来源 IP
- 新建 zvol 默认 `-s`（稀疏），不会预留全部空间；池剩余空间不足时会写入失败

## ZFS 管理

### 存储池

列出池的名称、健康、已用/总量、使用率。选中后可以：

- 查看大小、已用、可用、健康、碎片
- 启动 `zpool scrub`

### 数据集

- 列表包含 filesystem 和 volume（zvol）
- **新建数据集**：父数据集、名称、可选配额；自动带 `acltype=posixacl`（Samba 权限模型依赖）
- **新建 zvol**：父数据集、名称、大小（默认稀疏 `-s`）
- **删除数据集**：需要输入完整名称；可选递归
  - 拒绝删除存储池根数据集
  - 拒绝删除仍有 SMB 共享的数据集
  - 拒绝删除正在被 iSCSI 磁盘使用的 zvol

### 加密数据集

- 数据集列表里加密项带 `[加密]` 标记
- 「密钥管理」列出所有加密数据集及状态：`available` / `unavailable`
- 操作：
  - **加载密钥**：输入密码（`keylocation=prompt`）
  - **卸载密钥**：数据集必须先卸载挂载点
  - **挂载 / 卸载挂载点**
- 新建数据集时可以勾选「创建加密数据集」，使用 `aes-256-gcm` + passphrase

现有加密数据集：

```
backup-1/xct258  aes-256-gcm  passphrase
hdd-1/xct258     aes-256-gcm  passphrase
```

注意：

- 密码不会保存到脚本或配置文件
- 卸载密钥前要先卸载挂载点；如果有 iSCSI 磁盘使用这个数据集里的 zvol，脚本会先摘掉 target 再卸载
- 递归加载/卸载会用到 `-r`
- 加密数据集的快照、复制和普通数据集一样；密钥未加载时无法挂载

### 加密数据集与 SMB / iSCSI

加密数据集设置为：

```bash
canmount=noauto
```

开机不会自动挂载。`NAS_BOOT_GUARD=1 nas` 由 systemd 调用，在任何 SMB/iSCSI 服务之前执行：

| 对象 | 未解锁时 |
|---|---|
| 直接指向加密数据集（或它内部）的 SMB 共享 | 不修改 SMB 共享配置；共享可能仍显示，但占位目录是 `0700`，客户端访问被拒绝 |
| 加密数据集作为子目录的上级共享（如 `hdd-1` → `/mnt/hdd-1`） | 共享正常；加密子目录可能显示为空目录，但 `0700 + chattr +i`，无法进入或写入 |
| 以该数据集 zvol 为后端的 iSCSI | 从实际 `saveconfig.json` 移除 target/LUN/backstore，客户端发现不到 |
| 挂载点 | `chattr +i`，防止写进父数据集的占位目录 |

解锁后：

1. `zfs load-key`
2. 如果 SMB 共享用到这个数据集，自动 `zfs mount`
3. 从期望配置恢复 iSCSI target/LUN，`targetctl restore`
4. 挂载点有残留时，先改名为 `<path>.orphan-<时间>`，不会直接覆盖

锁定/卸载顺序：

```
摘掉 iSCSI target → 卸载挂载点 → unload-key → chattr +i
```

相关文件：

```
/var/lib/nas/hdd-sleep.json                机械硬盘休眠设置
/var/lib/nas/hdd-status.json               机械硬盘状态/上次变化/历史事件
/var/lib/nas/push.json                     休眠唤醒推送提醒配置
/var/lib/nas/iscsi-desired.json            iSCSI 完整期望配置
/etc/rtslib-fb-target/saveconfig.json      当前实际导出
/etc/systemd/system/nas-lock-guard.service
```

说明：

- 脚本不再修改 `smb.conf` 的 `available`、`hide unreadable` 或 `veto files`
- 未解锁时，占位目录设为 `0700`、清空 ACL、加 `chattr +i`
- 共享本身和加密子目录可能仍然出现在 SMB 列表里，但客户端访问会失败
- 不同层级的同名目录互不影响
- 如果共享配置了 `force user = root`，SMB 以 root 身份读取，`0700` 仍可访问；占位目录仍受 `chattr +i` 保护
- 新建/修改共享指向未解锁数据集会被拒绝；已解锁但未挂载时会自动挂载
- 加密父数据集下不允许创建未加密子数据集
- 卸载密钥后，iSCSI 客户端需要重新扫描/重连；SMB 需要重新打开共享

### 快照

- 列表显示名称、创建时间、占用
- 创建：选择数据集，输入名称（默认 `manual_YYYYmmdd_HHMM`），可选递归
- 回滚：需要输入完整快照名，警告会丢弃之后的数据；可选 `-R`
- 删除：需要输入完整快照名，可选递归

注意：

- 删除数据集/快照不可恢复
- 对正在被 iSCSI 客户端使用的 zvol 做回滚风险很高，先断开客户端
- 回滚不会影响其他数据集

## 系统集成 / 一键配置

主菜单「系统集成 / 一键配置」用于新机器初始化，也可以随时重复执行：

1. 检查依赖，缺失的可以直接安装
2. 给所有加密数据集设置 `canmount=noauto`
3. 写入并启用 `nas-lock-guard.service`、`nas-hdd-sleep.service`、`nas-hdd-monitor.service`
4. 启用 `smbd`、`nmbd`、`wsdd2`、`rtslib-fb-targetctl`、`zfs-import-cache`、`zfs-mount`、`zfs-zed`
5. 生成/同步 `/var/lib/nas/iscsi-desired.json`
6. 清理旧版 SMB 锁定配置，并应用一次 iSCSI 锁定状态

开机保护单元：

```ini
[Unit]
Description=NAS locked dataset guard (iSCSI / mountpoints)
After=zfs-import.target zfs-mount.service
Before=smbd.service nmbd.service wsdd2.service rtslib-fb-targetctl.service

[Service]
Type=oneshot
Environment=NAS_BOOT_GUARD=1
ExecStart=/usr/local/bin/nas
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

检查：

```bash
systemctl status nas-lock-guard.service
systemctl is-enabled zfs-load-key.service   # 应为 masked
zfs get canmount,keystatus,mounted backup-1/xct258 hdd-1/xct258
```

换一台新系统：

```bash
# 1. 拷贝脚本和文档
install -m 755 nas /usr/local/bin/nas
install -D -m 644 README.md /usr/local/share/doc/nas/README.md

# 2. 运行并选择「系统集成 / 一键配置」
nas
```

如果要从旧机器迁移共享和 iSCSI：

```bash
# 共享、用户、可见性
/etc/samba/smb.conf
/etc/passwd /etc/group /etc/shadow /etc/gshadow
/var/lib/nas/

# iSCSI 期望配置
/var/lib/nas/iscsi-desired.json

# ZFS 池本身
zpool import ...
```

迁移后重新执行一次「系统集成 / 一键配置」，会补上 `canmount=noauto` 和开机保护单元。

## 硬盘管理

主菜单「硬盘管理」提供物理磁盘和 ZFS 池的底层操作。

### 磁盘列表 / SMART

列出 `lsblk` 检测到的整盘：

```text
sdb  223.6G  SSD  sata  TOSHIBA-TR200   [cache-1]
sdd  [hdd-1]  931.5G  HDD  sata  ST1000DM010
```

选中后显示：

- 设备、容量、HDD/SSD、接口
- 型号
- 所属 ZFS 池
- 分区、文件系统、挂载点
- SMART 健康、温度、通电小时

SMART 操作：

- 短自检 `smartctl -t short`
- 长自检 `smartctl -t long`
- 查看自检结果 `smartctl -l selftest`

需要 `smartmontools`。未安装时对应的依赖项会显示在依赖检查里。

### 机械硬盘休眠

主菜单会直接提示未设置休眠的机械盘，例如：

```text
休眠   2 块机械盘未设置（sde、sdf）
```

全部设置后显示：

```text
休眠   机械盘已全部设置
```

设置入口：「硬盘管理 → 机械硬盘休眠」。

只列出 `rota=1` 的机械硬盘，例如：

```text
sdd  [hdd-1]   931.5G   休眠 10 分钟   当前 活动
sde  [backup-1] 14.6T   休眠 关闭       当前 活动
```

选中后可以：

- 设置空闲休眠时间：5 / 10 / 15 / 20 / 30 / 60 / 120 / 180 分钟
- 立即休眠
- 取消休眠设置
- 刷新当前电源状态

实际执行：

```bash
hdparm -S <值> /dev/sdX
hdparm -y /dev/sdX       # 立即休眠
hdparm -S 0 /dev/sdX     # 取消
```

时间换算：

| 分钟 | hdparm -S |
|---|---|
| 5 | 60 |
| 10 | 120 |
| 15 | 180 |
| 20 | 240 |
| 30 | 241 |
| 60 | 242 |
| 120 | 244 |
| 180 | 246 |

设置保存在：

```text
/var/lib/nas/hdd-sleep.json
```

开机由 `nas-hdd-sleep.service` 在 ZFS 导入后、SMB/iSCSI 启动前重新应用。

### 休眠状态监控

`nas-hdd-monitor.service` 在**至少一块机械盘配置了休眠**，或**空间监控开启**时运行，默认每 60 秒检查一次：

```bash
hdparm -C /dev/sdX
```

它不会执行 SMART 读取，也不会主动唤醒硬盘，只检查电源状态，并：

- 把当前状态写到 `/var/lib/nas/hdd-status.json`
- 记录每块盘上一次状态变化时间
- 保存每块盘最近 **50 条**唤醒/休眠事件
- 状态从 `活动 -> 已休眠`、`已休眠 -> 活动` 时写 journal

界面「机械硬盘休眠」直接读取这个状态文件，显示：

```text
sdd  [hdd-1]  931.5G  休眠 关闭  当前 活动  上次 11-04 10:22
```

选中硬盘后可以打开「查看唤醒/休眠记录」：

```text
时间                    事件
2026-11-04 10:22:03     唤醒
2026-11-04 10:22:01     休眠
```

### 异常唤醒保护

休眠的目的不是让硬盘反复启停。以下两种情况会自动取消该盘休眠，保持常转：

1. **睡眠后过早唤醒**
   - 例如设置为 5 分钟
   - 硬盘进入休眠后，5 分钟内（加一个检查周期容差）又被唤醒
   - 视为异常唤醒

2. **48 小时内被唤醒 3 次**
   - 即使每次都在休眠时间之后才唤醒
   - 从设置休眠的时间开始计算
   - 满 3 次也视为异常唤醒

触发后：

- 删除该盘的休眠设置
- 执行 `hdparm -S 0`，保持常转
- 写入 `/var/lib/nas/hdd-sleep-alerts.json`
- 主菜单显示：

```text
休眠保护  1 块盘异常唤醒已取消（sdd）
```

- 休眠列表里对应盘显示 `[异常唤醒-已取消]`
- 详情里显示取消原因和时间

处理方式：

- 如果确实需要重新休眠，在详情里重新设置休眠时间
  - 会清除告警
  - 重新开始计算 48 小时窗口
- 如果希望保持常转，选择「清除异常提示」

日志：

```bash
journalctl -u nas-hdd-monitor.service -f
```

调整检查间隔：

```bash
systemctl edit nas-hdd-monitor.service
```

加入：

```ini
[Service]
Environment=NAS_HDD_MONITOR_INTERVAL=120
```

然后：

```bash
systemctl restart nas-hdd-monitor.service
```

说明：

- 每块盘最多保留 50 条事件，超出后自动丢弃最旧的
- 事件只在监控服务运行期间记录；服务停止期间的切换会在下次启动时按当前状态补一条
- 监控服务只观察状态，不负责让硬盘休眠
- 休眠计时仍由 `nas-hdd-sleep.service` 和 `hdparm -S` 负责
- 如果硬盘盒不支持电源状态查询，会显示「未知」
- 更新脚本后建议重启一次监控服务

注意：

- ZFS 的 scrub、trim、SMB/iSCSI 访问、SMART 自检都会把盘唤醒
- 休眠时间太短会增加启停次数，不建议对频繁访问的盘设置 5 分钟
- 机械盘在 ZFS 池里能休眠，但效果取决于访问频率和 ZFS 后台活动
- USB 硬盘盒可能不支持 `hdparm -S`，会显示驱动错误
- 休眠只影响机械盘，SSD 不会出现在这个列表里

### 休眠推送提醒

「机械硬盘休眠 → 推送提醒设置」可以把休眠/唤醒事件推送到推送服务，配置保存在 `/var/lib/nas/push.json`，默认接口：

```text
https://push-server.o1-1.xct258.top/api/push
```

覆盖事件：

- 已设置休眠的机械盘每次**进入休眠**
- 每次**被唤醒**
- 如果唤醒同时触发了异常唤醒保护，状态为 `warn`，内容里会带上取消原因

通知参数：`category=service`、`msg_type=markdown`、`mode=append`，状态为 `ok`（休眠）/ `info`（唤醒）/ `warn`（异常唤醒）。关闭总开关后不会发送任何请求。

推送正文包含设备、型号、ZFS 池、当前状态、休眠设置、时间和异常处理原因。空间不足/恢复也会复用同一推送配置。

记录模式：

- 硬盘休眠/唤醒：`append`，保留历史
- 空间不足/恢复：`overwrite`，同一池只保留最新记录

设置项：

| 项目 | 说明 |
|---|---|
| 开启 / 关闭 | 总开关，默认关闭 |
| 推送地址 | 默认 `https://push-server.o1-1.xct258.top/api/push` |
| server_name | 来源名称，默认主机名；只允许字母、数字、点、下划线、短横线 |
| topic | 默认 `nas/hdd-sleep`；允许字母、数字、点、下划线、短横线、斜杠 |
| MQTT | 开启时 `push_to_mqtt=true`；关闭时只在服务端保存记录 |
| 发送测试推送 | 立即发一条测试通知，不受总开关影响 |

说明：

- 推送由 `nas-hdd-monitor.service` 执行；监控服务未安装或未运行时不发送
- 只推送已经设置休眠的机械盘，SSD 和未设置休眠的盘不会产生通知
- 推送失败只写入 journal，不会影响休眠监控
- 测试推送会真实调用接口；检查 `journalctl -u nas-hdd-monitor.service -f` 可以看发送失败原因

### 硬盘空间监控

主菜单：「硬盘管理 → 空间监控」。

监控**系统盘**和**已挂载的 ZFS 池**，同时显示具体容量和剩余百分比：

```text
系统盘 /   剩余 44.0G / 59.4G（74.0%）     阈值 10%   正常
hdd-1      剩余 40.0G / 953.9G（4.2%）     阈值 10%   不足
backup-1   剩余 8.4T / 14.6T（57.6%）      阈值 5%    正常
cache-1    剩余 144.9G / 223.6G（64.8%）   阈值 10%   正常
```

- 系统盘检查的是挂载点 `/`
- 总开关：开启 / 关闭
- 系统盘和各池分别设置阈值（0–99%）
- 阈值设为 `0` 表示该项不提醒
- 默认阈值为 `10%`

低于阈值时：

- 发送推送（需要「休眠 → 推送提醒设置」已开启）
- ZFS 池推送包含池名、可用 / 总容量、百分比、阈值、健康状态
- 系统盘推送包含分区、文件系统、可用 / 总容量、百分比、阈值
- 主菜单显示：

```text
空间告警  2 处（系统盘、hdd-1）
```

- 告警状态写入：

```text
/var/lib/nas/space-alerts.json
```

- 同一个目标不会每 60 秒重复推送，默认 6 小时后再次提醒
- 空间不足/恢复推送使用 `mode=overwrite`，同一目标只保留最新一条记录
- 空间恢复到阈值以上后，会发送一条“空间已恢复”并清除告警
- 关闭空间监控会清除当前空间告警

配置保存在：

```text
/var/lib/nas/space-monitor.json
```

示例：

```json
{
  "enabled": true,
  "system_threshold": 10,
  "thresholds": {
    "hdd-1": 10,
    "backup-1": 5,
    "cache-1": 0
  }
}
```

说明：

- 系统盘通过 `statvfs("/")` 读取，不依赖 `df`
- 只检查根数据集处于挂载状态的 ZFS 池
- 百分比按 `free / size` 计算
- 系统盘 / ZFS 池空间监控和 HDD 休眠监控共用 `nas-hdd-monitor.service`
- 只要“休眠设置”或“空间监控”任一开启，监控服务就会保持运行

## 创建 ZFS 池

- 只列出没有分区、文件系统、ZFS 成员的整盘
- 支持 `stripe`、`mirror`、`raidz1`、`raidz2`、`raidz3`
- 校验最少磁盘数
- 需要输入池名确认，因为会清除磁盘上的分区和文件系统

实际执行等价于：

```bash
zpool create -f -m /mnt/<池名> \
  -o ashift=12 \
  -O acltype=posixacl \
  -O compression=lz4 \
  -O xattr=sa \
  <池名> <布局> <磁盘...>
```

注意：

- 使用 `-f`，会覆盖磁盘签名
- 池根数据集自动 `acltype=posixacl`，Samba 权限模型可以直接使用
- 挂载点是 `/mnt/<池名>`
- 不会自动创建共享或数据集

### 导入 ZFS 池

- 列出 `zpool import` 可导入的池
- 普通导入失败时，可以再选择 `-f` 强制导入
- 适用于从其他系统迁移过来的池、hostid 不一致等情况
- 导入后执行一次 iSCSI 锁定状态刷新
- 加密数据集仍然保持锁定，需要到「ZFS 管理 → 密钥管理」解锁

## 依赖检查 / 安装

主菜单「依赖检查 / 安装」会实时显示：

```
ZFS                已安装 · 4 个池
SMB                已安装 · smbd active · nmbd active
iSCSI              已安装 · 服务 active
网络发现 (wsdd2)    已安装 · 服务 active
```

只对**缺失**的组件提供安装项，也可以「安装所有缺失项」。

安装过程：

```bash
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends <packages>
systemctl enable --now <services>
```

对应关系：

| 组件 | 软件包 | 服务 |
|---|---|---|
| ZFS | `zfsutils-linux`、`zfs-dkms`、`linux-headers-$(uname -r)` | 无 |
| SMB | `samba`、`acl`、`e2fsprogs`（`chattr`） | `smbd`、`nmbd` |
| iSCSI | `targetcli-fb` | `rtslib-fb-targetctl` |
| 网络发现 | `wsdd2` | `wsdd2` |
| 硬盘工具 | `smartmontools` | 无（可选） |
| 休眠工具 | `hdparm` | 无（可选） |

注意：

- 需要能访问 Debian 软件源
- 安装前会显示即将安装的包并要求确认
- ZFS 在 Debian 属于 `contrib`；一键安装会自动补源
- 需要当前内核的 `linux-headers` 才能编译 `zfs-dkms`

## 网络发现

SMB 管理里的「网络发现管理」是一个子菜单，包含：

- 开启 / 关闭网络发现
- 设置网络发现名称，1–15 个字符
- 刷新状态

子菜单顶部显示当前状态、名称、workgroup 和 smbd/nmbd/wsdd2 服务状态。

**开启**：

```ini
netbios name     = NAS
local master     = yes
preferred master = yes
os level         = 65
```

同时写入 wsdd2 的 systemd override：

```text
/etc/systemd/system/wsdd2.service.d/zz-nas-name.conf
```

内容：

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/wsdd2 -H NAS -N NAS -G WORKGROUP
```

然后执行：

```bash
systemctl daemon-reload
systemctl enable --now wsdd2
systemctl restart nmbd
```

**设置名称**：

```text
SMB 管理 → 网络发现管理 → 设置网络发现名称
```

名称规则：

- 1–15 个字符
- 以字母或数字开头
- 只能包含字母、数字、下划线、短横线

修改后会同时更新：

- `smb.conf` 的 `netbios name`
- `wsdd2` 的 `-H` / `-N` 名称
- 如果网络发现已开启，自动重启 `wsdd2` 和 `nmbd`

Windows 可能缓存旧名称，修改后建议刷新「网络」或重启客户端。

**关闭**：

```bash
systemctl disable --now wsdd2
```

并把 `local master` / `preferred master` 设为 `no`。`nmbd` 仍然运行，所以 `\\NAS` 和 `\\IP` 直接访问不受影响，只是不再主动出现在「网络」列表里。

Windows 侧需要：

- 网络配置文件为「专用网络」
- 开启「网络发现」和「文件和打印机共享」
- `FDResPub`、`fdPHost` 服务运行

## 安全与写入流程

任何 `smb.conf` 修改都会：

1. 生成新内容到临时文件
2. 用 `testparm -s` 校验，失败则不落盘
3. 备份到 `/var/backups/nas`（保留 20 份）
4. 原子 `rename` 覆盖
5. `smbcontrol smbd reload-config` 热加载（不断连接）

路径限制在 `NAS_ROOTS` 内，拒绝 `..` 和换行；外部命令全部用参数数组调用，不经过 shell。

## 环境变量

| 变量 | 默认 |
|---|---|
| `NAS_SMB_CONF` | `/etc/samba/smb.conf` |
| `NAS_BACKUP_DIR` | `/var/backups/nas` |
| `NAS_ROOTS` | `/mnt,/srv,/home` |
| `NAS_STATE_DIR` | `/var/lib/nas`（可见性、硬盘休眠/状态/告警、iSCSI 期望配置） |
| `NAS_SKIP_RELOAD` | `0`（设为 1 不执行 smbcontrol，测试用） |
| `NAS_BOOT_GUARD` | 由 `nas-lock-guard.service` 设为 `1`，只执行开机保护 |
| `NAS_HDD_SLEEP` | 由 `nas-hdd-sleep.service` 设为 `1`，只应用硬盘休眠设置 |
| `NAS_HDD_MONITOR` | 由 `nas-hdd-monitor.service` 设为 `1`，运行状态监控 |
| `NAS_NO_SELF_INSTALL` | `0`（设为 1 禁止自动安装/更新） |

## 常见问题

**重启后 hdd-1 里面的 xct258 还在，但进不去**

这是预期行为。加密数据集未解锁时，占位目录是 `0700 root:root` 并加了 `chattr +i`。

脚本不再修改 SMB 配置，所以目录可能仍然显示；客户端访问会被拒绝。解锁并挂载后内容恢复。

**重启后加密数据集的共享进不去 / iSCSI 盘不见了**

这是预期行为。加密数据集 `canmount=noauto`，开机不加载密钥、不挂载。进入：

```
ZFS 管理 → 密钥管理 → 加载密钥
```

脚本会按需挂载并恢复 iSCSI。

**解锁后 SMB 共享还是进不去**

确认数据集已经挂载，并且共享路径的父目录 ACL 允许访问。检查：

```bash
grep -A12 '^\[共享名\]' /etc/samba/smb.conf
smbclient -L //127.0.0.1 -N
```

**解锁后 iSCSI 客户端看不到盘**

target/LUN 已由 `targetctl restore` 恢复，Windows 里重新扫描磁盘；Linux 用 `iscsiadm -m session --rescan`。

**看到 `<路径>.orphan-<时间>` 目录**

说明解锁时挂载点里有残留文件（通常是未解锁期间写进父数据集的数据）。脚本没有覆盖或删除，而是改名留档。确认内容后自行处理。

**系统没有 Python / 运行提示未找到 python3**

脚本第一层是 `/bin/sh` 启动器，会提示：

```text
错误: 未找到 python3。
请以 root 执行: apt-get update && apt-get install -y python3
```

安装后重新运行即可：

```bash
apt-get update
apt-get install -y python3
```

如果 Python 版本低于 3.10，也会提示升级。

**Windows 资源管理器看不到 NAS**

1. 确认 SMB 管理里的「网络发现」是开
2. `systemctl is-active wsdd2 nmbd`
3. Windows 开启网络发现，检查 `FDResPub`、`fdPHost`
4. 直接用 `\\NAS` 或 `\\<IP>` 访问

**root 在服务器上改了文件，SMB 客户端很久才刷新**

先确认 Samba 的 lease 配置：

```bash
testparm -s --parameter-name='kernel oplocks'
testparm -s --parameter-name='smb2 leases'
smbstatus -L
```

应启用：

```ini
kernel oplocks = yes
```

否则本机 root 的写入无法及时打断 Windows 持有的 SMB lease，客户端会继续用旧缓存。

一键系统集成会自动写入这个设置。修改后需要：

```bash
systemctl restart smbd
```

然后 Windows 断开重连。

如果仍然延迟，再区分：

- 直接用 `\\192.168.50.4\共享名`，不要用映射盘
- 换另一台 SMB 客户端（手机/另一台 Linux）看是否立即出现
- 如果其他客户端立即出现，问题在 Windows 客户端缓存或“脱机文件”
- 可以临时加 `smb2 leases = no` 测试，但不建议长期关闭

**重置权限时报 No such file or directory**

旧版本会重新写入保留的 ACL，遇到悬空符号链接会失败。2.0 起改为只删除勾选的条目并跳过符号链接，不会再报这个错。

**权限看起来对，但还是访问不了**

```bash
getfacl -p /mnt/...
namei -l /mnt/...
```

逐层检查父目录是否有 `x` 权限；ACL 的 mask 也可能把权限压掉。

## 备份与恢复

```bash
ls -lt /var/backups/nas
cp /var/backups/nas/smb.conf.<时间戳>.bak /etc/samba/smb.conf
testparm -s && systemctl reload smbd
```
