#!/bin/sh
''''command -v python3 >/dev/null 2>&1 || {
    echo "错误: 未找到 python3。" >&2
    echo "请以 root 执行: apt-get update && apt-get install -y python3" >&2
    exit 1
}
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null || {
    echo "错误: nas 需要 Python 3.10 或更高版本。" >&2
    echo "当前: $(python3 --version 2>&1)" >&2
    echo "请升级 python3 后重试。" >&2
    exit 1
}
exec python3 "$0" "$@"
# '''
"""nas — 极简 Samba 共享、用户权限与 iSCSI 管理。

设计原则
  * 只依赖 Python 3 标准库，不需要 venv、Node 或守护进程。
  * 只改 smb.conf 中自己管理的行，注释和未知参数原样保留。
  * 写入前用 testparm 校验，失败不落盘；写入时备份 + 原子替换。
  * 不用 shell 拼接命令，路径/共享名不会进入命令行解释器。

环境变量
  NAS_SMB_CONF     默认 /etc/samba/smb.conf
  NAS_BACKUP_DIR   默认 /var/backups/nas
  NAS_ROOTS        允许的共享路径前缀，默认 /mnt,/srv,/home
  NAS_SKIP_RELOAD  设为 1 时不执行 smbcontrol reload（测试用）
"""


import fcntl
import grp
import json
import os
import pwd
import re
import secrets
import select
import shutil
import subprocess
import sys
import termios
import time
import tty
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

try:
    import curses
except ImportError:  # 极少见：无 curses 的 Python 环境退回原来的 ANSI 界面
    curses = None

VERSION = "9.8"

SMB_CONF = Path(os.environ.get("NAS_SMB_CONF", "/etc/samba/smb.conf"))
BACKUP_DIR = Path(os.environ.get("NAS_BACKUP_DIR", "/var/backups/nas"))
STATE_DIR = Path(os.environ.get("NAS_STATE_DIR", "/var/lib/nas"))
STATE_FILE = STATE_DIR / "visibility.json"
LOCKED_SHARES_FILE = STATE_DIR / "locked-shares.json"
VETO_SHARES_FILE = STATE_DIR / "veto-shares.json"
HIDE_SHARES_FILE = STATE_DIR / "hide-unreadable-shares.json"
HDD_SLEEP_FILE = STATE_DIR / "hdd-sleep.json"
AUTO_SNAP_FILE = STATE_DIR / "auto-snapshot.json"
AUTO_SNAP_UNIT = Path("/etc/systemd/system/nas-auto-snapshot.service")
AUTO_SNAP_TIMER = Path("/etc/systemd/system/nas-auto-snapshot.timer")
AUTO_SNAP_PREFIX = "auto-"
HDD_SLEEP_UNIT = Path("/etc/systemd/system/nas-hdd-sleep.service")
HDD_STATUS_FILE = STATE_DIR / "hdd-status.json"
HDD_ALERT_FILE = STATE_DIR / "hdd-sleep-alerts.json"
SPACE_MONITOR_FILE = STATE_DIR / "space-monitor.json"
SPACE_ALERT_FILE = STATE_DIR / "space-alerts.json"
SPACE_REALERT_SECONDS = 6 * 3600
MONITOR_LOCK_FILE = STATE_DIR / "monitor.lock"
SPACE_LOCK_FILE = STATE_DIR / "space-check.lock"
HDD_MONITOR_UNIT = Path("/etc/systemd/system/nas-hdd-monitor.service")
PUSH_FILE = STATE_DIR / "push.json"
PUSH_DEFAULT_URL = "https://push-server.o1-1.xct258.top/api/push"
PUSH_DEFAULT_TOPIC = "nas/hdd-sleep"
PUSH_TIMEOUT = 8
HDD_SLEEP = os.environ.get("NAS_HDD_SLEEP") == "1"
HDD_MONITOR = os.environ.get("NAS_HDD_MONITOR") == "1"
ISCSI_DESIRED = STATE_DIR / "iscsi-desired.json"
APT_DIR = Path(os.environ.get("NAS_APT_DIR", "/etc/apt"))
GUARD_UNIT = Path("/etc/systemd/system/nas-lock-guard.service")
INSTALL_PATH = Path(os.environ.get("NAS_INSTALL_PATH", "/usr/local/bin/nas"))
BOOT_GUARD = os.environ.get("NAS_BOOT_GUARD") == "1"
AUTO_SNAPSHOT = os.environ.get("NAS_AUTO_SNAPSHOT") == "1"
ALLOWED_ROOTS = [
    Path(p).resolve()
    for p in os.environ.get("NAS_ROOTS", "/mnt,/srv,/home").split(",")
    if p.strip()
]
SKIP_RELOAD = os.environ.get("NAS_SKIP_RELOAD") == "1"

SYSTEM_SECTIONS = {"global", "printers", "print$", "homes", "ipc$"}
SHARE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$\-]{0,79}$")

SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
PARAM_RE = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9 _:.\-]*?)\s*=\s*(.*)$")
ERROR_RE = re.compile(r"\bERROR\b|Error loading|Unknown parameter|is not a valid", re.I)


class NasError(Exception):
    pass


def _script_version(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return ""
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else ""


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for item in version.split("."):
        match = re.match(r"\d+", item)
        if not match:
            return ()
        parts.append(int(match.group(0)))
    return tuple(parts)


def _install_self(source: Path, target: Path) -> bool:
    try:
        data = source.read_bytes()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o755)
        os.replace(tmp, target)
        return True
    except OSError as exc:
        print(f"警告: 无法写入 {target}: {exc}", file=sys.stderr)
        return False


def self_install() -> None:
    """把自己安装/更新到 /usr/local/bin/nas。"""
    if os.environ.get("NAS_NO_SELF_INSTALL") == "1":
        return
    if os.geteuid() != 0:
        return
    if "__file__" not in globals():
        return
    try:
        source = Path(__file__).resolve()
    except OSError:
        return
    target = INSTALL_PATH
    try:
        if source == target.resolve():
            return
    except OSError:
        pass
    if not source.exists():
        return

    if target.exists():
        try:
            if source.read_bytes() == target.read_bytes():
                return
        except OSError:
            pass

        target_version = _script_version(target)
        if target_version and _version_tuple(target_version) > _version_tuple(VERSION):
            print(
                f"提示: {target} 是 {target_version}，比当前 {VERSION} 新，未降级。",
                file=sys.stderr,
            )
            return

        if not _install_self(source, target):
            return
        print(
            f"已更新 {target}: {target_version or '未知版本'} -> {VERSION}"
        )
    else:
        if not _install_self(source, target):
            return
        print(f"已安装脚本到 {target}")

    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execv(str(target), [str(target), *sys.argv[1:]])
    except OSError:
        pass

# ---------------------------------------------------------------- utilities


def run(args, *, input=None, check=False, timeout=60):
    try:
        proc = subprocess.run(
            args,
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except FileNotFoundError:
        raise NasError(f"命令不存在: {args[0]}") from None
    except subprocess.TimeoutExpired:
        raise NasError(f"命令超时: {args[0]}") from None
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[:400]
        raise NasError(f"{' '.join(args)} 失败: {detail}")
    return proc


def need_root() -> None:
    if os.geteuid() != 0:
        raise NasError("该操作需要 root 权限")


def confirm(message: str, token: str) -> None:
    if not sys.stdin.isatty():
        raise NasError("非交互环境请加 --yes")
    answer = read_line(f"{message}\n请输入 {token} 确认: ")
    if answer != token:
        raise NasError("已取消")


def check_share_name(name: str) -> str:
    name = name.strip()
    if not SHARE_NAME_RE.fullmatch(name):
        raise NasError("共享名只能包含字母、数字、点、下划线、$ 和短横线，且不能以符号开头")
    if name.lower() in SYSTEM_SECTIONS:
        raise NasError(f"该名称是 Samba 保留段名: {name}")
    return name


def check_path(path: str, *, create: bool = False) -> Path:
    if not path or "\n" in path or "\r" in path or "\x00" in path:
        raise NasError("路径不合法")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise NasError("路径必须是绝对路径")

    if candidate.exists():
        resolved = candidate.resolve()
    elif create:
        try:
            parent = candidate.parent.resolve(strict=True)
        except OSError:
            raise NasError(f"父路径不存在: {candidate.parent}") from None
        if not parent.is_dir():
            raise NasError(f"父路径不是目录: {parent}")
        resolved = parent / candidate.name
    else:
        raise NasError(f"路径不存在: {candidate}")

    if not any(resolved == root or root in resolved.parents for root in ALLOWED_ROOTS):
        roots = ", ".join(str(r) for r in ALLOWED_ROOTS)
        raise NasError(f"路径不在允许范围（{roots}）: {resolved}")
    return resolved


# ---------------------------------------------------------------- smb.conf


class Block:
    def __init__(self, name: str, header: str):
        self.name = name
        self.header = header
        self.lines: list[str] = []

    def params(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in self.lines:
            if line.lstrip().startswith(("#", ";")):
                continue
            match = PARAM_RE.match(line)
            if match:
                out[match.group(2).strip().lower()] = match.group(3).strip()
        return out


class SmbConf:
    def __init__(self, path: Path):
        self.path = path
        self.preamble: list[str] = []
        self.blocks: list[Block] = []

    def load(self) -> "SmbConf":
        if not self.path.exists():
            raise NasError(f"找不到 Samba 配置文件: {self.path}")
        self.preamble = []
        self.blocks = []
        current: Block | None = None
        text = self.path.read_text(encoding="utf-8", errors="surrogateescape")
        for line in text.splitlines(keepends=True):
            match = SECTION_RE.match(line)
            if match:
                current = Block(match.group(1).strip(), line)
                self.blocks.append(current)
            elif current is None:
                self.preamble.append(line)
            else:
                current.lines.append(line)
        if not any(block.name.lower() == "global" for block in self.blocks):
            self.blocks.insert(0, Block("global", "[global]\n"))
        return self

    def find(self, name: str) -> Block | None:
        needle = name.strip().lower()
        return next((b for b in self.blocks if b.name.lower() == needle), None)

    def shares(self) -> list[Block]:
        return [b for b in self.blocks if b.name.lower() not in SYSTEM_SECTIONS]

    def upsert(self, name: str, values: dict[str, str | None]) -> None:
        block = self.find(name)
        if block is None:
            block = Block(name, f"[{name}]\n")
            self.blocks.append(block)
        for key, value in values.items():
            self._set(block, key, value)

    @staticmethod
    def _set(block: Block, key: str, value: str | None) -> None:
        key_l = key.strip().lower()
        pattern = re.compile(r"^\s*" + re.escape(key_l) + r"\s*=", re.IGNORECASE)
        hits = [i for i, line in enumerate(block.lines) if pattern.match(line)]

        if value is None or str(value).strip() == "":
            for index in reversed(hits):
                del block.lines[index]
            return

        new_line = f"\t{key_l} = {str(value).strip()}\n"
        if hits:
            block.lines[hits[0]] = new_line
            for index in reversed(hits[1:]):
                del block.lines[index]
            return

        at = len(block.lines)
        while at > 0 and not block.lines[at - 1].strip():
            at -= 1
        block.lines.insert(at, new_line)

    def remove(self, name: str) -> None:
        block = self.find(name)
        if block is None:
            raise NasError(f"共享不存在: {name}")
        if block.name.lower() in SYSTEM_SECTIONS:
            raise NasError(f"系统共享不允许删除: {block.name}")
        self.blocks.remove(block)

    def rename(self, old: str, new: str) -> None:
        block = self.find(old)
        if block is None:
            raise NasError(f"共享不存在: {old}")
        other = self.find(new)
        if other is not None and other is not block:
            raise NasError(f"共享名已被占用: {new}")
        if block.name.lower() in SYSTEM_SECTIONS:
            raise NasError(f"系统共享不允许重命名: {block.name}")
        block.name = new
        block.header = f"[{new}]\n"

    def render(self) -> str:
        parts: list[str] = []
        for line in self.preamble:
            parts.append(line if line.endswith("\n") else line + "\n")
        for index, block in enumerate(self.blocks):
            parts.append(block.header if block.header.endswith("\n") else block.header + "\n")
            for line in block.lines:
                parts.append(line if line.endswith("\n") else line + "\n")
            if index != len(self.blocks) - 1:
                ends_blank = bool(block.lines) and not block.lines[-1].strip()
                if not ends_blank:
                    parts.append("\n")
        return "".join(parts)

    def save(self, *, reload: bool = True) -> dict:
        content = self.render()
        tmp = self.path.with_name(f".{self.path.name}.nas-tmp")

        with open(tmp, "w", encoding="utf-8", errors="surrogateescape") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copymode(self.path, tmp)

        problems = validate_conf(tmp)
        if problems:
            tmp.unlink(missing_ok=True)
            raise NasError("配置校验失败，未写入:\n  " + "\n  ".join(problems))

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
        backup = BACKUP_DIR / f"{self.path.name}.{stamp}.bak"
        shutil.copy2(self.path, backup)
        os.replace(tmp, self.path)
        prune_backups()
        if reload:
            reload_samba()
        return {"backup": str(backup)}


def validate_conf(path: Path) -> list[str]:
    if not shutil.which("testparm"):
        return []
    proc = run(["testparm", "-s", "--suppress-prompt", str(path)])
    output = f"{proc.stdout}\n{proc.stderr}"
    problems = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and ERROR_RE.search(line)
    ]
    if proc.returncode != 0 and not problems:
        problems.append(f"testparm 退出码 {proc.returncode}")
    return problems


def prune_backups(keep: int = 20) -> None:
    backups = sorted(BACKUP_DIR.glob("*.bak"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[keep:]:
        old.unlink(missing_ok=True)


def reload_samba() -> None:
    if SKIP_RELOAD:
        return
    proc = run(["smbcontrol", "smbd", "reload-config"])
    if proc.returncode != 0:
        run(["systemctl", "reload", "smbd"])


def reload_share_security() -> None:
    """sharesec 修改后必须 SIGHUP，smbcontrol reload-config 不会刷新共享 SD。"""
    if SKIP_RELOAD:
        return
    run(["systemctl", "reload", "smbd"], check=False)


# ---------------------------------------------------------------- locked state

def _path_under(path: str, root: str) -> bool:
    if not path or not root:
        return False
    p = os.path.normpath(path)
    r = os.path.normpath(root)
    return p == r or p.startswith(r.rstrip("/") + "/")


def locked_encrypted_datasets() -> list[dict]:
    """密钥未加载的加密数据集。"""
    if not zfs_available():
        return []
    try:
        rows = zfs_encrypted_datasets()
    except NasError:
        return []
    return [r for r in rows if r.get("keystatus") != "available"]


def blocked_share_datasets() -> list[dict]:
    """SMB 不可用的加密文件系统：未解锁，或已解锁但没挂载。"""
    if not zfs_available():
        return []
    try:
        rows = zfs_encrypted_datasets()
    except NasError:
        return []
    result = []
    for row in rows:
        if row.get("type") != "filesystem":
            continue
        mountpoint = row.get("mountpoint") or ""
        if not mountpoint.startswith("/"):
            continue
        if row.get("keystatus") != "available" or row.get("mounted") != "yes":
            result.append(row)
    return result


def share_path_blocked(path: str, rows: list[dict] | None = None) -> dict | None:
    if rows is None:
        rows = blocked_share_datasets()
    for row in rows:
        if _path_under(path, row.get("mountpoint", "")):
            return row
    return None


def ensure_share_path_unlocked(path: Path | str) -> None:
    target = str(path)
    for _ in range(16):
        matches = [
            row for row in blocked_share_datasets()
            if _path_under(target, row.get("mountpoint", ""))
        ]
        if not matches:
            return
        matches.sort(key=lambda row: len(row.get("mountpoint", "")), reverse=True)
        row = matches[0]
        if row.get("keystatus") == "available" and row.get("type") == "filesystem":
            # 已解锁但没挂载：加共享时顺手挂上，避免写进父数据集的占位目录
            mount_dataset_safe(row["name"])
            continue
        raise NasError(
            f"数据集 {row['name']} 未解锁，"
            "请先在 ZFS 管理 → 密钥管理中加载密钥"
        )
    raise NasError("共享路径的加密数据集层级过深，无法确认挂载状态")


def load_locked_shares() -> dict[str, str]:
    try:
        data = json.loads(LOCKED_SHARES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def save_locked_shares(data: dict[str, str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = LOCKED_SHARES_FILE.with_name(LOCKED_SHARES_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, LOCKED_SHARES_FILE)


def load_veto_shares() -> dict[str, list[str]]:
    """旧版 6.5 的 veto 状态，仅用于升级清理。"""
    try:
        data = json.loads(VETO_SHARES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(k): [str(item) for item in v]
        for k, v in data.items() if isinstance(v, list)
    }


def save_veto_shares(data: dict[str, list[str]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = VETO_SHARES_FILE.with_name(VETO_SHARES_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, VETO_SHARES_FILE)


def load_hide_shares() -> dict[str, list[str]]:
    try:
        data = json.loads(HIDE_SHARES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(k): [str(item) for item in v]
        for k, v in data.items() if isinstance(v, list)
    }


def save_hide_shares(data: dict[str, list[str]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = HIDE_SHARES_FILE.with_name(HIDE_SHARES_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, HIDE_SHARES_FILE)


def apply_share_locks(*, reload: bool = True) -> list[tuple[str, str, bool]]:
    """兼容清理旧版本设置；新版本不再对锁定数据集做 SMB 特殊处理。"""
    state = load_locked_shares()
    hide_state = load_hide_shares()
    legacy_veto = load_veto_shares()
    if not SMB_CONF.exists():
        save_locked_shares({})
        save_hide_shares({})
        save_veto_shares({})
        return []

    conf = SmbConf(SMB_CONF).load()
    conf_changed = False
    names: set[str] = set()

    for block in conf.shares():
        names.add(block.name)
        params = block.params()

        if block.name in state:
            if params.get("available", "yes").lower() == "no":
                conf.upsert(block.name, {"available": None})
                conf_changed = True
            state.pop(block.name, None)

        if block.name in hide_state:
            if params.get("hide unreadable", "").lower() in {"yes", "true", "1", "on"}:
                conf.upsert(block.name, {"hide unreadable": None})
                conf_changed = True
            hide_state.pop(block.name, None)

        old_patterns = legacy_veto.get(block.name, [])
        if old_patterns:
            existing = params.get("veto files", "").split()
            remaining = [item for item in existing if item not in old_patterns]
            if remaining:
                if " ".join(remaining) != params.get("veto files", ""):
                    conf.upsert(block.name, {"veto files": " ".join(remaining)})
                    conf_changed = True
            else:
                conf.upsert(block.name, {"veto files": None})
                conf_changed = True
            legacy_veto.pop(block.name, None)

    if conf_changed:
        conf.save(reload=reload)
    save_locked_shares({})
    save_hide_shares({})
    save_veto_shares({})
    return []

def set_immutable(path: str | Path | None, enabled: bool) -> bool:
    """锁定未挂载的挂载点，防止通过父目录写进加密数据集的占位目录。"""
    if not path:
        return False
    target = Path(path)
    if not target.exists():
        return False
    flag = "+i" if enabled else "-i"
    proc = run(["chattr", flag, str(target)], check=False)
    if proc.returncode == 0:
        return True
    if enabled:
        # chattr 不可用时退化为 root-only，并清掉可能残留的 ACL
        run(["chmod", "0700", str(target)], check=False)
        run(["setfacl", "-b", str(target)], check=False)
    return False


def lock_mountpoint(row: dict) -> None:
    if row.get("type") != "filesystem" or row.get("mounted") == "yes":
        return
    mountpoint = row.get("mountpoint") or ""
    if not mountpoint.startswith("/") or not Path(mountpoint).exists():
        return
    # 先去掉旧的 immutable，再让目录对非 root 完全不可读/不可进入
    set_immutable(mountpoint, False)
    run(["setfacl", "-b", mountpoint], check=False)
    run(["chmod", "0700", mountpoint], check=False)
    set_immutable(mountpoint, True)


def _rename_orphan(mountpoint: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = Path(f"{mountpoint}.orphan-{stamp}")
    index = 1
    while target.exists():
        target = Path(f"{mountpoint}.orphan-{stamp}-{index}")
        index += 1
    try:
        os.rename(mountpoint, target)
    except OSError as exc:
        raise NasError(
            f"挂载点有残留且无法移走: {mountpoint}: {exc.strerror or exc}"
        ) from None
    return target


def mount_dataset_safe(dataset: str) -> bool:
    """解锁后挂载；挂载点有残留时先改名留档，不直接覆盖。"""
    info = zfs_props(dataset, ["type", "mounted", "keystatus", "mountpoint"])
    if info.get("type") != "filesystem":
        return False
    if info.get("mounted") == "yes":
        return False
    if info.get("keystatus") not in (None, "-", "available"):
        raise NasError(f"密钥未加载，无法挂载: {dataset}")
    mountpoint = info.get("mountpoint") or ""
    if not mountpoint.startswith("/"):
        raise NasError(f"数据集没有可用的挂载点: {dataset}")

    if Path(mountpoint).exists():
        set_immutable(mountpoint, False)
        try:
            residue = os.listdir(mountpoint)
        except OSError as exc:
            raise NasError(f"无法读取挂载点 {mountpoint}: {exc.strerror or exc}") from None
        if residue:
            orphan = _rename_orphan(mountpoint)
            print(f"挂载点有残留，已移到: {orphan}")

    try:
        run(["zfs", "mount", dataset], check=True)
    except NasError:
        row = {"type": "filesystem", "mounted": "no", "mountpoint": mountpoint}
        lock_mountpoint(row)
        raise
    return True


def mount_datasets_for_shares() -> list[str]:
    """只挂载被 SMB 共享用到的加密数据集；zvol 不需要挂载。"""
    if not zfs_available() or not SMB_CONF.exists():
        return []
    try:
        shares = [
            block.params().get("path", "")
            for block in SmbConf(SMB_CONF).load().shares()
        ]
    except NasError:
        return []
    shares = [path for path in shares if path]
    if not shares:
        return []

    try:
        rows = zfs_encrypted_datasets()
    except NasError:
        return []
    candidates = [
        row for row in rows
        if row.get("type") == "filesystem"
        and row.get("keystatus") == "available"
        and row.get("mounted") != "yes"
    ]
    candidates.sort(key=lambda row: row.get("name", "").count("/"))
    mounted = []
    for row in candidates:
        mountpoint = row.get("mountpoint") or ""
        if not mountpoint.startswith("/"):
            continue
        if not any(
            _path_under(path, mountpoint) or _path_under(mountpoint, path)
            for path in shares
        ):
            continue
        if mount_dataset_safe(row["name"]):
            mounted.append(row["name"])
    return mounted


# ---------------------------------------------------------------- share ops


def report(action: str, detail: str, result: dict) -> None:
    print(f"{action} {detail}")
    if result.get("backup"):
        print(f"备份: {result['backup']}")


def user_sid(name: str) -> str:
    proc = run(["pdbedit", "-L", "-v", name])
    if proc.returncode != 0:
        raise NasError(f"{name} 没有 Samba 账户，无法设置共享可见性")
    for line in proc.stdout.splitlines():
        if line.startswith("User SID:"):
            return line.split(":", 1)[1].strip()
    raise NasError(f"无法获取 {name} 的 SID")


def read_share_acl(share: str) -> list[str]:
    proc = run(["sharesec", "-s", str(SMB_CONF), share, "--view"])
    return [
        line[4:].strip()
        for line in proc.stdout.splitlines()
        if line.startswith("ACL:")
    ]


def apply_share_acl(share: str, aces: list[str]) -> None:
    if aces:
        run(["sharesec", "-s", str(SMB_CONF), share, "-R", ",".join(aces)], check=True)


def clear_share_acl(share: str) -> None:
    run(["sharesec", "-s", str(SMB_CONF), share, "-D"], check=False)


def load_visibility() -> dict[str, list[str]]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_visibility(data: dict[str, list[str]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def acl_user_names(path: Path) -> list[str]:
    """共享根目录访问 ACL 里的具名用户（不含数字 UID 和 root）。"""
    proc = run(["getfacl", "-p", "-E", str(path)])
    names = set()
    for line in proc.stdout.splitlines():
        if not line.startswith("user:"):
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        name = parts[1]
        if name and not name.isdigit() and name != "root":
            names.add(name)
    return sorted(names)


def sync_visibility(share: str, path: str) -> None:
    """文件系统 ACL 变化后，按当前 ABSE 状态重建共享 ACL。"""
    conf = SmbConf(SMB_CONF).load()
    block = conf.find(share)
    if block is None:
        return
    params = block.params()
    if params.get("access based share enum", "no").lower() not in {"yes", "true", "1", "on"}:
        return
    if share_path_blocked(path) is not None:
        return

    accounts = samba_account_names()
    authorized = [name for name in acl_user_names(Path(path)) if name in accounts]
    state = load_visibility()
    extras = [
        name for name in state.get(share, [])
        if name in accounts and name not in authorized
    ]

    writable = params.get("read only", "yes").lower() not in {"yes", "true", "1", "on"}
    parts = [
        f"{user_sid(name)}:ALLOWED/0x0/{'FULL' if writable else 'READ'}"
        for name in authorized
    ]
    parts += [f"{user_sid(name)}:ALLOWED/0x0/READ" for name in extras]

    if parts:
        run(["sharesec", "-s", str(SMB_CONF), share, "-R", ",".join(parts)], check=True)
    else:
        # 没有任何可见/有权限用户：拒绝所有人，保持隐藏
        run(["sharesec", "-s", str(SMB_CONF), share, "-R", "S-1-1-0:DENIED/0x0/FULL"],
            check=True)

    state[share] = extras
    save_visibility(state)
    reload_share_security()
    if extras:
        print("额外可见：" + "、".join(extras))
    if authorized:
        print("有权限用户：" + "、".join(authorized))


def apply_visibility(share: str, path: str, hide: bool, extras: list[str], writable: bool) -> None:
    ensure_share_path_unlocked(path)
    accounts = samba_account_names()
    authorized = [name for name in acl_user_names(Path(path)) if name in accounts]
    extras = [name for name in extras if name in accounts]
    if hide and not authorized:
        raise NasError("共享根目录还没有具名用户 ACL，无法确定谁有权限；请先设置权限")

    conf = SmbConf(SMB_CONF).load()
    # 不使用 valid users：它会让不在名单里的“额外可见”用户也无法枚举。
    # 访问控制交给共享 ACL（谁能连接）+ 文件系统 ACL（能看什么）。
    if hide:
        conf.upsert(share, {
            "valid users": None,
            "access based share enum": "yes",
        })
    else:
        conf.upsert(share, {"valid users": None, "access based share enum": None})
    result = conf.save()

    state = load_visibility()
    if hide:
        parts = [
            f"{user_sid(name)}:ALLOWED/0x0/{'FULL' if writable else 'READ'}"
            for name in authorized
        ]
        parts += [
            f"{user_sid(name)}:ALLOWED/0x0/READ"
            for name in extras
            if name not in authorized
        ]
        run(["sharesec", "-s", str(SMB_CONF), share, "-R", ",".join(parts)], check=True)
        state[share] = [name for name in extras if name not in authorized]
    else:
        clear_share_acl(share)
        state.pop(share, None)
    save_visibility(state)
    reload_share_security()
    report("已更新可见性", share, result)


def cmd_share_add(args) -> None:
    need_root()
    name = check_share_name(args.name)
    path = check_path(args.path, create=args.create_dir)
    ensure_share_path_unlocked(path)
    if args.create_dir and not path.exists():
        path.mkdir(mode=0o770)
        os.chown(path, 0, 0)

    conf = SmbConf(SMB_CONF).load()
    if conf.find(name):
        raise NasError(f"共享已存在: {name}")

    values: dict[str, str | None] = {
        "path": str(path),
        "comment": args.comment,
        "browseable": "no" if args.hidden else "yes",
        "read only": "yes" if args.read_only else "no",
        "guest ok": "yes" if args.guest else "no",
        # 属主固定 root，新建内容继承目录属主；权限只通过 ACL 授予
        "inherit owner": "windows and unix",
        "create mask": "0770",
        "force create mode": "0110",
        "directory mask": "0770",
    }
    # 文件系统侧默认拒绝：root:root，目录 2770、文件 0770
    try:
        os.chown(path, 0, 0)
        os.chmod(path, 0o2770)
    except OSError as exc:
        raise NasError(f"无法设置 {path} 的属主/权限: {exc.strerror or exc}") from None

    hide = getattr(args, "hide_visibility", None)
    if hide and not acl_user_names(path):
        raise NasError("共享目录还没有具名用户 ACL，无法确定谁有权限；请先创建共享并设置权限")

    conf.upsert(name, values)
    result = conf.save()
    report("已添加共享", f"{name} -> {path}", result)
    if hide is not None:
        apply_visibility(name, str(path), hide, list(getattr(args, "extra_visible", None) or []),
                         not args.read_only)


def cmd_share_edit(args) -> None:
    need_root()
    conf = SmbConf(SMB_CONF).load()
    block = conf.find(args.name)
    if block is None:
        raise NasError(f"共享不存在: {args.name}")
    if block.name.lower() in SYSTEM_SECTIONS:
        raise NasError(f"系统共享不允许修改: {block.name}")

    target = block.name
    values: dict[str, str | None] = {}

    if args.new_name:
        new_name = check_share_name(args.new_name)
        conf.rename(target, new_name)
        target = new_name

    if args.path:
        new_path = check_path(args.path, create=args.create_dir)
        ensure_share_path_unlocked(new_path)
        if args.create_dir and not new_path.exists():
            new_path.mkdir(mode=0o770)
            os.chown(new_path, 0, 0)
        values["path"] = str(new_path)
    if args.comment is not None:
        values["comment"] = args.comment
    if args.read_only is not None:
        values["read only"] = "yes" if args.read_only else "no"
    if args.browseable is not None:
        values["browseable"] = "yes" if args.browseable else "no"
    if args.guest is not None:
        values["guest ok"] = "yes" if args.guest else "no"

    hide = getattr(args, "hide_visibility", None)
    if not values and target == args.name and hide is None:
        raise NasError("没有需要修改的内容")

    old_acl: list[str] = []
    if target != args.name and hide is None:
        old_acl = read_share_acl(args.name)

    conf.upsert(target, values)
    result = conf.save()
    current_ro = block.params().get("read only", "yes").lower() in {"yes", "true", "1", "on"}
    if "read only" in values:
        current_ro = values["read only"] == "yes"
    writable = not current_ro

    if target != args.name:
        if old_acl:
            apply_share_acl(target, old_acl)
        clear_share_acl(args.name)
        state = load_visibility()
        if args.name in state:
            state[target] = state.pop(args.name)
            save_visibility(state)
        locked = load_locked_shares()
        if args.name in locked:
            locked[target] = locked.pop(args.name)
            save_locked_shares(locked)
        hidden = load_hide_shares()
        if args.name in hidden:
            hidden[target] = hidden.pop(args.name)
            save_hide_shares(hidden)
        legacy_veto = load_veto_shares()
        if args.name in legacy_veto:
            legacy_veto[target] = legacy_veto.pop(args.name)
            save_veto_shares(legacy_veto)
        reload_share_security()

    if hide is not None:
        effective_path = values.get("path") or block.params().get("path", "")
        apply_visibility(target, str(check_path(effective_path)), hide,
                         list(getattr(args, "extra_visible", None) or []), writable)
    apply_share_locks()
    report("已更新共享", target, result)


def cmd_share_rm(args) -> None:
    need_root()
    conf = SmbConf(SMB_CONF).load()
    block = conf.find(args.name)
    if block is None:
        raise NasError(f"共享不存在: {args.name}")
    if block.name.lower() in SYSTEM_SECTIONS:
        raise NasError(f"系统共享不允许删除: {block.name}")

    if not args.yes:
        confirm(f"将删除共享配置 {block.name}（磁盘文件不会删除）", block.name)

    clear_share_acl(block.name)
    state = load_visibility()
    if block.name in state:
        state.pop(block.name, None)
        save_visibility(state)
    locked = load_locked_shares()
    if block.name in locked:
        locked.pop(block.name, None)
        save_locked_shares(locked)
    hidden = load_hide_shares()
    if block.name in hidden:
        hidden.pop(block.name, None)
        save_hide_shares(hidden)
    legacy_veto = load_veto_shares()
    if block.name in legacy_veto:
        legacy_veto.pop(block.name, None)
        save_veto_shares(legacy_veto)

    conf.remove(block.name)
    result = conf.save()
    reload_share_security()
    report("已删除共享", block.name, result)


def share_mode_values() -> dict[str, str | None]:
    return {
        "inherit owner": "windows and unix",
        "create mask": "0770",
        "force create mode": "0110",
        "directory mask": "0770",
    }


def ensure_smb_coherence() -> None:
    """本机写入也要能及时打断 SMB lease/oplock 缓存。"""
    conf = SmbConf(SMB_CONF).load()
    block = conf.find("global")
    if block is None:
        return
    if block.params().get("kernel oplocks", "").lower() not in {"yes", "true", "1", "on"}:
        conf.upsert("global", {"kernel oplocks": "yes"})
        conf.save()


def ensure_share_exec_defaults() -> None:
    conf = SmbConf(SMB_CONF).load()
    changed = False
    for block in conf.shares():
        params = block.params()
        wanted = share_mode_values()
        if any(str(params.get(key, "")).lower() != str(value or "").lower()
               for key, value in wanted.items()):
            conf.upsert(block.name, wanted)
            changed = True
    if changed:
        conf.save()



def _exec_find_args(target: Path) -> list[str]:
    return [
        "find", str(target), "-xdev", "-type", "f", "(",
        "-iname", "*.exe", "-o", "-iname", "*.com", "-o",
        "-iname", "*.bat", "-o", "-iname", "*.cmd", "-o",
        "-iname", "*.msi", "-o", "-iname", "*.scr", "-o",
        "-iname", "*.ps1", "-o", "-iname", "*.vbs",
        ")", "-print",
    ]


def cmd_share_fix_exec(args) -> None:
    need_root()
    block, target = share_target(args.share)
    names = acl_user_names(target)
    specs = ["u::rwx", "g::rwx", "m::rwx"]
    specs += [f"u:{name}:rwx" for name in names]
    spec = ",".join(specs)
    find_args = _exec_find_args(target)
    probe = run(find_args, check=False, timeout=300)
    paths = [line for line in probe.stdout.splitlines() if line.strip()]
    if not paths:
        print("没有找到可执行扩展名的文件。")
        return
    exec_args = find_args[:-1] + ["-exec", "setfacl", "-m", spec, "{}", "+"]
    run(exec_args, check=True, timeout=600)
    run(["systemctl", "reload", "smbd"], check=False)
    print(f"已修复 {len(paths)} 个可执行文件的权限。")
    print("Windows 端断开重连后再运行。")


# ---------------------------------------------------------------- acl

ACL_PERMS_RE = re.compile(r"^[rwx]{1,3}$")


def _check_principal(kind: str, name: str) -> None:
    if not name:
        raise NasError("用户/组名不能为空")
    if name.isdigit():
        return
    try:
        if kind == "user":
            pwd.getpwnam(name)
        else:
            grp.getgrnam(name)
    except KeyError:
        raise NasError(f"系统{'用户' if kind == 'user' else '组'}不存在: {name}") from None


def parse_acl_specs(users: list[str], groups: list[str]) -> list[dict]:
    entries: list[dict] = []
    for kind, values in (("user", users or []), ("group", groups or [])):
        for item in values:
            if "=" not in item:
                raise NasError(f"格式应为 name=rwx: {item}")
            name, perms = item.split("=", 1)
            name, perms = name.strip(), perms.strip()
            _check_principal(kind, name)
            if not ACL_PERMS_RE.fullmatch(perms):
                raise NasError(f"权限只能是 r/w/x 的组合: {perms or '(空)'}")
            entries.append({
                "type": kind,
                "name": name,
                "perms": "".join(ch for ch in "rwx" if ch in perms),
            })
    return entries


def share_target(share: str) -> tuple[Block, Path]:
    conf = SmbConf(SMB_CONF).load()
    block = conf.find(share)
    if block is None:
        raise NasError(f"共享不存在: {share}")
    path = block.params().get("path")
    if not path:
        raise NasError(f"共享 {share} 没有配置路径")
    target = Path(path)
    ensure_share_path_unlocked(target)
    if not target.exists():
        raise NasError(f"共享路径不存在: {target}")
    return block, target


def _walk_same_dev(target: Path):
    root_dev = os.stat(target).st_dev
    for root, dirs, files in os.walk(target, followlinks=False):
        keep = []
        for name in dirs:
            child = os.path.join(root, name)
            try:
                if os.path.islink(child):
                    continue
                if os.stat(child).st_dev != root_dev:
                    continue
            except OSError:
                continue
            keep.append(name)
        dirs[:] = keep
        yield Path(root), files


def apply_owner_mode(target: Path, recursive: bool) -> int:
    """root:root，目录 2770、文件 0770；不跨越子数据集。"""
    changed = 0

    def one(item: Path, is_dir: bool) -> None:
        nonlocal changed
        try:
            os.chown(item, 0, 0)
            os.chmod(item, 0o2770 if is_dir else 0o770)
            changed += 1
        except OSError as exc:
            raise NasError(f"无法修改 {item}: {exc.strerror or exc}") from None

    if recursive:
        if not target.is_dir():
            raise NasError("递归操作要求目标是目录")
        for root, files in _walk_same_dev(target):
            one(root, True)
            for name in files:
                item = root / name
                if not item.is_symlink():
                    one(item, False)
    else:
        one(target, target.is_dir())
    return changed


def print_acl(target: Path) -> None:
    proc = run(["getfacl", "-p", str(target)])
    if proc.returncode != 0:
        raise NasError((proc.stderr or proc.stdout).strip()[:300])
    print(proc.stdout.rstrip())


def cmd_acl_set(args) -> None:
    need_root()
    block, target = share_target(args.share)
    entries = parse_acl_specs(args.user, args.group)
    if not entries:
        raise NasError("至少指定一个 --user 或 --group")

    changed = apply_owner_mode(target, args.recursive)

    access = ",".join(
        f"{'u' if e['type'] == 'user' else 'g'}:{e['name']}:{e['perms']}" for e in entries
    )
    defaults = ",".join(
        f"d:{'u' if e['type'] == 'user' else 'g'}:{e['name']}:{e['perms']}" for e in entries
    )

    if args.recursive:
        run([
            "find", str(target), "-xdev", "(", "-type", "f", "-o", "-type", "d", ")",
            "-exec", "setfacl", "-m", access, "{}", "+",
        ], check=True)
    else:
        run(["setfacl", "-m", access, str(target)], check=True)

    if target.is_dir():
        if args.recursive:
            run(["find", str(target), "-xdev", "-type", "d",
                 "-exec", "setfacl", "-m", defaults, "{}", "+"], check=True)
        else:
            run(["setfacl", "-m", defaults, str(target)], check=True)

    # 让之后通过 SMB 新建的内容也符合这个模型
    conf = SmbConf(SMB_CONF).load()
    conf.upsert(block.name, share_mode_values())
    result = conf.save()

    report("已设置权限", f"{block.name}（{changed} 个条目）", result)
    print_acl(target)
    sync_visibility(block.name, str(target))


def cmd_acl_reset(args) -> None:
    """只收回勾选的 ACL 条目，可选重置属主/基础权限。"""
    need_root()
    block, target = share_target(args.share)

    revoke = {tuple(item.split(":", 1)) for item in (args.revoke or [])}

    if not revoke and not args.reset_base:
        raise NasError("没有选择要收回的 ACL，也没有选择重置基础权限")

    changed = 0
    if args.reset_base:
        changed = apply_owner_mode(target, args.recursive)

    if revoke:
        access = ",".join(
            f"{'u' if kind == 'user' else 'g'}:{name}" for kind, name in revoke
        )
        defaults = ",".join(
            f"d:{'u' if kind == 'user' else 'g'}:{name}" for kind, name in revoke
        )
        # 只处理普通文件和目录，跳过符号链接（悬空链接会让 setfacl 报错）
        run([
            "find", str(target), "-xdev", "(", "-type", "f", "-o", "-type", "d", ")",
            "-exec", "setfacl", "-x", access, "{}", "+",
        ], check=True)
        if target.is_dir():
            run([
                "find", str(target), "-xdev", "-type", "d",
                "-exec", "setfacl", "-x", defaults, "{}", "+",
            ], check=True)

    result = None
    if args.reset_base:
        conf = SmbConf(SMB_CONF).load()
        conf.upsert(block.name, share_mode_values())
        result = conf.save()

    summary = f"{block.name}（收回 {len(revoke)} 项，其余保持不动）"
    if result:
        report("已重置共享权限", summary, result)
    else:
        print(f"已重置 {summary}")
    if args.reset_base:
        print(f"属主/基础权限已重置为 root:root，目录 2770 / 文件 0770（{changed} 个条目）。")
    print_acl(target)
    if revoke:
        keep = set(getattr(args, "keep_visible", None) or [])
        revoked_users = {name for kind, name in revoke if kind == "user"}
        state = load_visibility()
        extras = set(state.get(block.name, []))
        extras |= (keep & revoked_users)
        state[block.name] = sorted(extras)
        save_visibility(state)
        sync_visibility(block.name, str(target))

def _service_state(name: str) -> str:
    proc = run(["systemctl", "is-active", name])
    return (proc.stdout or proc.stderr).strip() or "unknown"


def discovery_enabled() -> bool:
    return _service_state("wsdd2") == "active"


def discovery_state() -> dict:
    conf = SmbConf(SMB_CONF).load()
    block = conf.find("global")
    params = block.params() if block else {}
    return {
        "netbios": params.get("netbios name", ""),
        "workgroup": params.get("workgroup", ""),
        "local_master": params.get("local master", ""),
        "preferred_master": params.get("preferred master", ""),
        "os_level": params.get("os level", ""),
        "nmbd": _service_state("nmbd"),
        "smbd": _service_state("smbd"),
        "wsdd2": _service_state("wsdd2"),
        "wsdd_installed": shutil.which("wsdd2") is not None,
    }


def cmd_discovery_status(args) -> None:
    state = discovery_state()
    print(f"netbios name : {state['netbios'] or '(未设置)'}")
    try:
        override = WSDD2_OVERRIDE.read_text(encoding="utf-8")
        wsdd_line = next((line for line in override.splitlines()
                          if line.startswith("ExecStart=")
                          and line.strip() != "ExecStart="), "")
        if wsdd_line and " -N " in wsdd_line:
            print(f"wsdd2 名称   : {wsdd_line.split(' -N ', 1)[1].split()[0]}")
    except OSError:
        pass
    print(f"workgroup    : {state['workgroup'] or '(未设置)'}")
    print(f"浏览主控     : local master={state['local_master'] or '-'} "
          f"preferred master={state['preferred_master'] or '-'} os level={state['os_level'] or '-'}")
    print(f"服务         : smbd={state['smbd']} nmbd={state['nmbd']} wsdd2={state['wsdd2']}")
    if not state["wsdd_installed"]:
        print("提示         : 未安装 wsdd2，Windows 10/11 可能不会在「网络」里显示")


def write_wsdd2_name(name: str, workgroup: str) -> bool:
    binary = shutil.which("wsdd2")
    if not binary:
        return False
    content = (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={binary} -H {name} -N {name} -G {workgroup}\n"
    )
    try:
        old = WSDD2_OVERRIDE.read_text(encoding="utf-8")
    except OSError:
        old = ""
    if old != content:
        WSDD2_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
        tmp = WSDD2_OVERRIDE.with_name(WSDD2_OVERRIDE.name + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, WSDD2_OVERRIDE)
        run(["systemctl", "daemon-reload"], check=False)
    return True


def cmd_discovery_on(args) -> None:
    need_root()
    if not shutil.which("wsdd2"):
        raise NasError("未安装 wsdd2，请先执行：apt install wsdd2")

    conf = SmbConf(SMB_CONF).load()
    current = (conf.find("global").params().get("netbios name", "") if conf.find("global") else "").strip()
    name = current if NETBIOS_RE.fullmatch(current) else "NAS"

    workgroup = conf.find("global").params().get("workgroup", "WORKGROUP") or "WORKGROUP"
    conf.upsert("global", {
        "netbios name": name,
        "local master": "yes",
        "preferred master": "yes",
        "os level": "65",
    })
    result = conf.save()
    write_wsdd2_name(name, workgroup)

    run(["systemctl", "enable", "--now", "wsdd2"], check=True)
    run(["systemctl", "restart", "nmbd"], check=True)
    report("已开启网络发现", f"netbios={name}", result)


def cmd_discovery_set_name(args) -> None:
    need_root()
    name = (args.name or "").strip()
    if not NETBIOS_RE.fullmatch(name):
        raise NasError("名称只能 1-15 个字符，以字母或数字开头，可含字母、数字、下划线、短横线")
    conf = SmbConf(SMB_CONF).load()
    workgroup = conf.find("global").params().get("workgroup", "WORKGROUP") or "WORKGROUP"
    conf.upsert("global", {"netbios name": name})
    result = conf.save()
    write_wsdd2_name(name, workgroup)
    if discovery_enabled():
        run(["systemctl", "restart", "wsdd2"], check=False)
        run(["systemctl", "restart", "nmbd"], check=False)
    report("已设置网络发现名称", name, result)


def cmd_discovery_off(args) -> None:
    need_root()
    conf = SmbConf(SMB_CONF).load()
    conf.upsert("global", {"local master": "no", "preferred master": "no"})
    result = conf.save()

    if shutil.which("wsdd2"):
        run(["systemctl", "disable", "--now", "wsdd2"])
    run(["systemctl", "restart", "nmbd"], check=True)
    report("已关闭网络发现", "wsdd2 已停止", result)
    print("nmbd 仍在运行，直接访问 \\\\NAS 或 IP 不受影响。")


# ---------------------------------------------------------------- users

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.\-]{0,31}$")
NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$")
WSDD2_OVERRIDE = Path("/etc/systemd/system/wsdd2.service.d/zz-nas-name.conf")


def linux_user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def list_samba_users() -> list[dict]:
    proc = run(["pdbedit", "-L"])
    if proc.returncode != 0:
        raise NasError((proc.stderr or proc.stdout).strip()[:300])
    rows = []
    for line in proc.stdout.splitlines():
        name = line.split(":", 1)[0].strip()
        if not name:
            continue
        detail = run(["pdbedit", "-Lv", name])
        flags = ""
        for item in detail.stdout.splitlines():
            if item.startswith("Account Flags:"):
                flags = item.split(":", 1)[1]
        rows.append({
            "name": name,
            "disabled": "D" in flags.replace("[", "").replace("]", ""),
            "linux": linux_user_exists(name),
        })
    return rows


def cmd_user_add(args) -> None:
    need_root()
    name = (args.name or "").strip()
    password = args.password or ""
    if not USERNAME_RE.fullmatch(name):
        raise NasError("用户名只能包含小写字母、数字、下划线、点和短横线，且以字母或下划线开头")
    if not password or "\n" in password or "\r" in password:
        raise NasError("密码不能为空且不能包含换行")
    if len(password) < 4:
        raise NasError("密码至少 4 位")
    if any(row["name"] == name for row in list_samba_users()):
        raise NasError(f"Samba 用户已存在: {name}")

    created_linux = False
    if not linux_user_exists(name):
        if not args.create_linux:
            raise NasError(f"Linux 用户 {name} 不存在；请勾选创建系统用户")
        run(["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", name], check=True)
        created_linux = True

    run(["smbpasswd", "-s", "-a", name], input=f"{password}\n{password}\n", check=True)
    run(["smbpasswd", "-e", name], check=False)
    print(f"已添加用户 {name}" + ("（同时创建了 Linux 系统用户）" if created_linux else ""))


def cmd_user_password(args) -> None:
    need_root()
    name = args.name
    password = args.password or ""
    if not any(row["name"] == name for row in list_samba_users()):
        raise NasError(f"Samba 用户不存在: {name}")
    if not password or "\n" in password or "\r" in password:
        raise NasError("密码不能为空且不能包含换行")
    if len(password) < 4:
        raise NasError("密码至少 4 位")
    run(["smbpasswd", "-s", name], input=f"{password}\n{password}\n", check=True)
    print(f"已重置 {name} 的密码")


def cmd_user_toggle(args) -> None:
    need_root()
    row = next((r for r in list_samba_users() if r["name"] == args.name), None)
    if row is None:
        raise NasError(f"Samba 用户不存在: {args.name}")
    enable = row["disabled"]
    run(["smbpasswd", "-e" if enable else "-d", args.name], check=True)
    print(f"已{'启用' if enable else '禁用'}用户 {args.name}")


def cmd_user_delete(args) -> None:
    need_root()
    name = args.name
    if not any(row["name"] == name for row in list_samba_users()):
        raise NasError(f"Samba 用户不存在: {name}")
    if name in {"root", "nobody"}:
        raise NasError("该账户受保护，不能删除")
    run(["smbpasswd", "-x", name], check=True)
    removed_linux = False
    if args.delete_linux and linux_user_exists(name):
        run(["userdel", name], check=True)
        removed_linux = True

    state = load_visibility()
    changed = False
    for names in state.values():
        if name in names:
            names.remove(name)
            changed = True
    if changed:
        save_visibility(state)

    for block in SmbConf(SMB_CONF).load().shares():
        path = block.params().get("path")
        if not path:
            continue
        try:
            sync_visibility(block.name, path)
        except NasError as exc:
            print(f"更新 {block.name} 可见性失败: {exc}")

    print(f"已删除 Samba 用户 {name}" + ("，并删除 Linux 用户" if removed_linux else ""))


# ---------------------------------------------------------------- iscsi

ISCSI_CONFIG = Path("/etc/rtslib-fb-target/saveconfig.json")
ISCSI_IQN_RE = re.compile(
    r"^(iqn\.[0-9]{4}-[0-9]{2}\.[A-Za-z0-9.-]+:[A-Za-z0-9._:-]+"
    r"|eui\.[0-9A-Fa-f]{16}|naa\.[0-9A-Fa-f]{16})$"
)
BACKSTORE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ZFS_SIZE_RE = re.compile(r"^[0-9]+(\.[0-9]+)?[KMGTP]?$", re.IGNORECASE)


def targetcli(*args, check: bool = True, timeout: int = 60):
    return run(["targetcli", *args], check=check, timeout=timeout)


def iscsi_config() -> dict:
    try:
        return json.loads(ISCSI_CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"storage_objects": [], "targets": []}


def iscsi_storage() -> list[dict]:
    return iscsi_config().get("storage_objects", [])


def iscsi_storage_by_name(name: str) -> dict | None:
    return next((s for s in iscsi_storage() if s.get("name") == name), None)


def _read_json_file(path: Path, fallback: dict) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback
    return data if isinstance(data, dict) else fallback


def _write_json_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def iscsi_desired_config() -> dict:
    """完整配置；锁定只是从实际 saveconfig 里过滤，期望配置始终保留。"""
    empty = {"storage_objects": [], "targets": []}
    if ISCSI_DESIRED.exists():
        return _read_json_file(ISCSI_DESIRED, empty)
    active = iscsi_config()
    if active.get("storage_objects") or active.get("targets"):
        _write_json_file(ISCSI_DESIRED, active)
    return active


def _merge_target_list(active_targets: list[dict], desired_targets: list[dict]) -> list[dict]:
    """targetcli saveconfig 以内核为准；内核偶尔会丢 node_acls，用期望配置补回。"""
    merged = list(active_targets)
    by_wwn = {target.get("wwn"): target for target in merged}
    for wanted in desired_targets:
        wwn = wanted.get("wwn")
        if wwn not in by_wwn:
            merged.append(wanted)
            continue
        current = by_wwn[wwn]
        current_tpgs = current.get("tpgs") or []
        wanted_tpgs = wanted.get("tpgs") or []
        for index, tpg in enumerate(current_tpgs):
            if index >= len(wanted_tpgs):
                continue
            current_acls = tpg.get("node_acls") or []
            wanted_acls = wanted_tpgs[index].get("node_acls") or []
            known = {acl.get("node_wwn") for acl in current_acls}
            for acl in wanted_acls:
                if acl.get("node_wwn") not in known:
                    current_acls.append(acl)
            if current_acls:
                tpg["node_acls"] = current_acls
    return merged


def iscsi_save(
    *, drop_targets=(), drop_stores=(), drop_acls=(), replace: bool = False
) -> dict:
    """targetcli saveconfig 后同步期望配置，保留因锁定而暂时隐藏的对象。"""
    targetcli("saveconfig")
    active = iscsi_config()
    if replace or not ISCSI_DESIRED.exists():
        merged = active
    else:
        desired = _read_json_file(
            ISCSI_DESIRED, {"storage_objects": [], "targets": []})
        active_stores = {s.get("name") for s in active.get("storage_objects", [])}
        merged = dict(active)
        merged["storage_objects"] = list(active.get("storage_objects", [])) + [
            s for s in desired.get("storage_objects", [])
            if s.get("name") not in active_stores
        ]
        merged["targets"] = _merge_target_list(
            list(active.get("targets", [])), desired.get("targets", []))

    drop_t = set(drop_targets)
    drop_s = set(drop_stores)
    if drop_t:
        merged["targets"] = [
            t for t in merged.get("targets", []) if t.get("wwn") not in drop_t
        ]
    if drop_s:
        merged["storage_objects"] = [
            s for s in merged.get("storage_objects", []) if s.get("name") not in drop_s
        ]
    if drop_acls:
        blocked = set(drop_acls)
        for target in merged.get("targets", []):
            for tpg in target.get("tpgs") or []:
                tpg["node_acls"] = [
                    acl for acl in tpg.get("node_acls") or []
                    if (target.get("wwn"), acl.get("node_wwn")) not in blocked
                ]
    _write_json_file(ISCSI_DESIRED, merged)
    return merged


def _zvol_dataset(dev: str) -> str:
    return dev[len("/dev/zvol/"):] if dev.startswith("/dev/zvol/") else ""


def _dataset_in(dataset: str, names: set[str]) -> bool:
    return any(dataset == name or dataset.startswith(name + "/") for name in names)


def apply_iscsi_locks(
    *, restore: bool = True, extra_locked=()
) -> tuple[list[str], list[str]]:
    """从实际导出配置里移除锁定数据集上的 backstore/LUN/target。"""
    if not shutil.which("targetcli"):
        return [], []
    if not ISCSI_CONFIG.exists() and not ISCSI_DESIRED.exists():
        return [], []

    desired = iscsi_desired_config()
    locked = {row["name"] for row in locked_encrypted_datasets()}
    locked.update(extra_locked)
    active = json.loads(json.dumps(desired))

    hidden_stores: set[str] = set()
    if locked:
        keep_stores = []
        for store in active.get("storage_objects", []):
            dataset = _zvol_dataset(store.get("dev", ""))
            if dataset and _dataset_in(dataset, locked):
                hidden_stores.add(store.get("name", ""))
                continue
            keep_stores.append(store)
        active["storage_objects"] = keep_stores

    hidden_targets: list[str] = []
    keep_targets = []
    for target in active.get("targets", []):
        tpgs = target.get("tpgs") or []
        had_luns = any(tpg.get("luns") for tpg in tpgs)
        for tpg in tpgs:
            original = tpg.get("luns") or []
            luns = []
            for lun in original:
                name = lun.get("storage_object", "").rsplit("/", 1)[-1]
                if name in hidden_stores:
                    continue
                luns.append(lun)
            if "luns" in tpg or luns:
                tpg["luns"] = luns
        if had_luns and not any(tpg.get("luns") for tpg in tpgs):
            hidden_targets.append(target.get("wwn", ""))
            continue
        keep_targets.append(target)
    active["targets"] = keep_targets

    current = iscsi_config()
    changed = active != current
    if changed:
        _write_json_file(ISCSI_CONFIG, active)
        if restore:
            proc = run(["targetctl", "restore"], check=False)
            if proc.returncode != 0:
                print(f"targetctl restore 失败: {(proc.stderr or proc.stdout).strip()[:300]}")
    return hidden_targets, sorted(hidden_stores)


def iscsi_suspended_summary() -> tuple[list[str], list[str]]:
    desired = iscsi_desired_config()
    active = iscsi_config()
    active_targets = {t.get("wwn") for t in active.get("targets", [])}
    active_stores = {s.get("name") for s in active.get("storage_objects", [])}
    targets = [
        t.get("wwn", "") for t in desired.get("targets", [])
        if t.get("wwn") not in active_targets
    ]
    stores = [
        s.get("name", "") for s in desired.get("storage_objects", [])
        if s.get("name") not in active_stores
    ]
    return targets, stores


def iscsi_storage_all() -> list[dict]:
    merged: dict[str, dict] = {}
    for config in (iscsi_config(), iscsi_desired_config()):
        for store in config.get("storage_objects", []):
            merged[store.get("name", "")] = store
    return list(merged.values())


def iscsi_targets() -> list[dict]:
    result = []
    for target in iscsi_config().get("targets", []):
        if target.get("fabric") != "iscsi":
            continue
        tpg = (target.get("tpgs") or [{}])[0]
        result.append({
            "iqn": target.get("wwn", ""),
            "luns": tpg.get("luns", []),
            "acls": tpg.get("node_acls", []),
            "portals": tpg.get("portals", []),
        })
    return result


def _size_text(size: int | None) -> str:
    if size is None:
        return "?"
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def zvol_list() -> list[tuple[str, int]]:
    proc = run(["zfs", "list", "-Hp", "-t", "volume", "-o", "name,volsize"])
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1].isdigit():
            rows.append((parts[0], int(parts[1])))
    return sorted(rows)


def iscsi_detail_lines(target: dict) -> list[str]:
    lines = []
    for lun in target["luns"]:
        obj = lun.get("storage_object", "").rsplit("/", 1)[-1]
        store = iscsi_storage_by_name(obj) or {}
        lines.append(f"LUN {lun.get('index')}  {store.get('dev', obj)}")
    portals = ", ".join(
        f"{p.get('ip_address')}:{p.get('port')}" for p in target["portals"]
    )
    lines.append(f"Portal {portals or '-'}")
    if target["acls"]:
        for acl in target["acls"]:
            user = acl.get("chap_userid") or "无 CHAP"
            lines.append(f"客户端 {acl.get('node_wwn')}  (CHAP {user})")
    else:
        lines.append("客户端 无（未授权任何 initiator）")
    return lines


def cmd_zfs_zvol(args) -> tuple[str, Path]:
    need_root()
    parent = args.parent.strip().strip("/")
    name = args.name.strip()
    size = args.size.strip()
    if not BACKSTORE_RE.fullmatch(name):
        raise NasError("zvol 名称只能包含字母、数字、下划线、点和短横线")
    if not ZFS_SIZE_RE.fullmatch(size):
        raise NasError("大小格式应类似 50G / 1T")
    proc = run(["zfs", "list", "-H", "-o", "name", parent], check=False)
    if proc.returncode != 0:
        raise NasError(f"父数据集不存在: {parent}")
    dataset = f"{parent}/{name}"
    if run(["zfs", "list", "-H", "-o", "name", dataset], check=False).returncode == 0:
        raise NasError(f"zvol 已存在: {dataset}")
    run(["zfs", "create", "-s", "-V", size, dataset], check=True)
    dev = Path("/dev/zvol") / dataset
    for _ in range(40):
        if dev.exists():
            break
        time.sleep(0.25)
    if not dev.exists():
        raise NasError(f"zvol 已创建但设备未出现: {dev}")
    return dataset, dev


def cmd_iscsi_service(args) -> None:
    need_root()
    action = args.action
    if action == "start":
        run(["systemctl", "enable", "--now", "rtslib-fb-targetctl"], check=True)
    elif action == "stop":
        run(["systemctl", "stop", "rtslib-fb-targetctl"], check=True)
    elif action == "restart":
        run(["systemctl", "restart", "rtslib-fb-targetctl"], check=True)
    else:
        raise NasError(f"未知操作: {action}")

    state = _service_state("rtslib-fb-targetctl")
    listening = ":3260" in run(["ss", "-tln"]).stdout
    targets = len(iscsi_targets())
    port = "监听中" if listening else ("未监听（当前没有 target）" if targets == 0 else "未监听")
    print(f"iSCSI 服务：{state}")
    print(f"target 数量：{targets}")
    print(f"3260 端口：{port}")


def cmd_iscsi_reset(args) -> None:
    need_root()
    targets = iscsi_targets()
    stores = iscsi_storage()
    for target in targets:
        targetcli("/iscsi", "delete", target["iqn"], check=False)
    if args.delete_backstores:
        for store in stores:
            targetcli("/backstores/block", "delete", store["name"], check=False)
    iscsi_save(replace=True)
    print(f"已删除 {len(targets)} 个 target"
          + (f"，{len(stores)} 个 backstore" if args.delete_backstores else "，保留 backstore"))


def cmd_iscsi_create(args) -> None:
    need_root()
    if not shutil.which("targetcli"):
        raise NasError("未安装 targetcli-fb")
    dev = Path(args.device)
    if not dev.exists():
        raise NasError(f"块设备不存在: {dev}")
    name = args.backstore
    iqn = args.target_iqn
    initiator = args.initiator
    if not BACKSTORE_RE.fullmatch(name):
        raise NasError("backstore 名称不合法")
    if not ISCSI_IQN_RE.fullmatch(iqn):
        raise NasError("target IQN 格式不正确")
    if not ISCSI_IQN_RE.fullmatch(initiator):
        raise NasError("initiator IQN 格式不正确")
    if any(store.get("name") == name for store in iscsi_storage_all()):
        raise NasError(f"backstore 已存在: {name}")
    desired_targets = iscsi_desired_config().get("targets", [])
    if any(t["iqn"] == iqn for t in iscsi_targets()) or \
            any(t.get("wwn") == iqn for t in desired_targets):
        raise NasError(f"target 已存在: {iqn}")
    if not args.chap_user or len(args.chap_password or "") < 8:
        raise NasError("CHAP 用户名不能为空，密码至少 8 位")

    run(["systemctl", "enable", "--now", "rtslib-fb-targetctl"], check=True)
    targetcli("/backstores/block", "create", f"name={name}", f"dev={dev}")
    targetcli("/iscsi", "create", iqn)
    targetcli(f"/iscsi/{iqn}/tpg1/luns", "create", f"/backstores/block/{name}")
    targetcli(f"/iscsi/{iqn}/tpg1", "set", "attribute",
              "authentication=1", "generate_node_acls=0",
              "demo_mode_write_protect=0", "cache_dynamic_acls=0")
    targetcli(f"/iscsi/{iqn}/tpg1/portals", "create", "0.0.0.0", "3260", check=False)
    targetcli(f"/iscsi/{iqn}/tpg1/acls", "create", initiator)
    targetcli(f"/iscsi/{iqn}/tpg1/acls/{initiator}", "set", "auth",
              f"userid={args.chap_user}", f"password={args.chap_password}")
    iscsi_save()
    print(f"已创建 iSCSI 磁盘 {iqn}")
    print(f"backstore {name} -> {dev}")


def cmd_iscsi_acl(args) -> None:
    need_root()
    target = next((t for t in iscsi_targets() if t["iqn"] == args.target), None)
    if target is None:
        raise NasError(f"target 不存在: {args.target}")
    if not ISCSI_IQN_RE.fullmatch(args.initiator):
        raise NasError("initiator IQN 格式不正确")
    if not args.chap_user or len(args.chap_password or "") < 8:
        raise NasError("CHAP 用户名不能为空，密码至少 8 位")
    existing = {a.get("node_wwn") for a in target["acls"]}
    if args.initiator not in existing:
        targetcli(f"/iscsi/{args.target}/tpg1/acls", "create", args.initiator)
    targetcli(f"/iscsi/{args.target}/tpg1/acls/{args.initiator}", "set", "auth",
              f"userid={args.chap_user}", f"password={args.chap_password}")
    iscsi_save()
    print(f"已授权 {args.initiator} 访问 {args.target}")


def cmd_iscsi_acl_delete(args) -> None:
    need_root()
    target = next((t for t in iscsi_targets() if t["iqn"] == args.target), None)
    if target is None:
        raise NasError(f"target 不存在: {args.target}")
    if not any(a.get("node_wwn") == args.initiator for a in target["acls"]):
        raise NasError(f"客户端不存在: {args.initiator}")
    targetcli(f"/iscsi/{args.target}/tpg1/acls", "delete", args.initiator)
    iscsi_save(drop_acls=[(args.target, args.initiator)])
    print(f"已移除客户端 {args.initiator}")


def cmd_iscsi_delete(args) -> None:
    need_root()
    target = next((t for t in iscsi_targets() if t["iqn"] == args.target_iqn), None)
    if target is None:
        raise NasError(f"target 不存在: {args.target_iqn}")
    backstore = ""
    if target["luns"]:
        backstore = target["luns"][0].get("storage_object", "").rsplit("/", 1)[-1]
    targetcli("/iscsi", "delete", args.target_iqn)
    if args.delete_backstore and backstore:
        targetcli("/backstores/block", "delete", backstore, check=False)
    iscsi_save(
        drop_targets=[args.target_iqn],
        drop_stores=[backstore] if args.delete_backstore and backstore else [],
    )
    print(f"已删除 iSCSI 磁盘 {args.target_iqn}" + ("（含 backstore）" if args.delete_backstore else ""))


# ---------------------------------------------------------------- deps

DEPENDENCIES = [
    {
        "key": "zfs", "name": "ZFS",
        "packages": ["zfsutils-linux", "zfs-dkms"],
        "commands": ["zfs", "zpool"],
        "services": [],
        "optional": False,
    },
    {
        "key": "smb", "name": "SMB",
        "packages": ["samba", "acl", "e2fsprogs"],
        "commands": ["smbd", "testparm", "setfacl", "chattr"],
        "services": ["smbd", "nmbd"],
        "optional": False,
    },
    {
        "key": "iscsi", "name": "iSCSI",
        "packages": ["targetcli-fb"],
        "commands": ["targetcli"],
        "services": ["rtslib-fb-targetctl"],
        "optional": False,
    },
    {
        "key": "wsdd", "name": "网络发现 (wsdd2)",
        "packages": ["wsdd2"],
        "commands": ["wsdd2"],
        "services": ["wsdd2"],
        "optional": True,
    },
    {
        "key": "smart", "name": "硬盘工具 (smartctl)",
        "packages": ["smartmontools"],
        "commands": ["smartctl"],
        "services": [],
        "optional": True,
    },
    {
        "key": "hdparm", "name": "休眠工具 (hdparm)",
        "packages": ["hdparm"],
        "commands": ["hdparm"],
        "services": [],
        "optional": True,
    },
]


def dependency_status() -> list[dict]:
    result = []
    for dep in DEPENDENCIES:
        ok = all(shutil.which(name) for name in dep["commands"])
        detail = "已安装"
        if dep["key"] == "zfs" and ok:
            proc = run(["zpool", "list", "-H", "-o", "name"], check=False)
            pools = len([line for line in proc.stdout.splitlines() if line.strip()])
            detail = f"已安装 · {pools} 个池"
        elif dep["key"] == "smb" and ok:
            detail = f"已安装 · smbd {_service_state('smbd')} · nmbd {_service_state('nmbd')}"
        elif dep["key"] == "iscsi" and ok:
            detail = f"已安装 · 服务 {_service_state('rtslib-fb-targetctl')}"
        elif dep["key"] == "wsdd" and ok:
            detail = f"已安装 · 服务 {_service_state('wsdd2')}"
        elif dep["key"] == "smart" and ok:
            detail = "已安装 · smartctl"
        elif dep["key"] == "hdparm" and ok:
            detail = "已安装 · hdparm"
        elif not ok:
            detail = "未安装" + ("（可选）" if dep["optional"] else "")

        result.append({
            "key": dep["key"],
            "name": dep["name"],
            "ok": ok,
            "detail": detail,
            "packages": dep["packages"],
            "services": dep["services"],
        })
    return result


def _debian_source(text: str) -> bool:
    return any(token in text for token in (
        "deb.debian.org", "security.debian.org",
        "mirror+file:///etc/apt/mirrors",
    ))


def ensure_contrib_sources() -> bool:
    """Debian 的 ZFS 在 contrib；裸机通常只有 main。"""
    candidates = [APT_DIR / "sources.list"]
    candidates += sorted((APT_DIR / "sources.list.d").glob("*.sources"))
    candidates += sorted((APT_DIR / "sources.list.d").glob("*.list"))
    changed = False
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="surrogateescape")
        except OSError:
            continue
        if not _debian_source(text):
            continue
        lines = text.splitlines(keepends=True)
        modified = False
        for index, line in enumerate(lines):
            stripped = line.lstrip()
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            body = line.rstrip("\r\n")
            if stripped.startswith("Components:"):
                value = body.split(":", 1)[1].strip()
                if "main" in value.split() and "contrib" not in value.split():
                    lines[index] = body + " contrib" + newline
                    modified = True
            elif stripped.startswith("deb ") and "main" in body.split() and "contrib" not in body.split():
                lines[index] = body + " contrib" + newline
                modified = True
        if not modified:
            continue
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, BACKUP_DIR / f"{path.name}.{stamp}.bak")
        tmp = path.with_name("." + path.name + ".nas-tmp")
        tmp.write_text("".join(lines), encoding="utf-8", errors="surrogateescape")
        os.replace(tmp, path)
        print(f"已启用 contrib 源: {path}")
        changed = True
    return changed


def cmd_deps_install(args) -> None:
    need_root()
    keys = set(args.keys or [])
    selected = [d for d in DEPENDENCIES if d["key"] in keys]
    if not selected:
        raise NasError("没有选择要安装的依赖")

    packages = sorted({pkg for dep in selected for pkg in dep["packages"]})
    print("将安装：" + " ".join(packages))
    if not ask_confirm("继续？", True):
        print("已取消")
        return

    if "zfs" in keys:
        ensure_contrib_sources()
    print("更新软件源…")
    run(["apt-get", "update"], check=False, timeout=300)

    if "zfs" in keys:
        headers = f"linux-headers-{os.uname().release}"
        probe = run(["apt-cache", "show", headers], check=False)
        if probe.returncode != 0:
            raise NasError(
                f"找不到 {headers}，无法编译 ZFS 模块；"
                "请先安装当前内核的头文件，或检查软件源"
            )
        packages.append(headers)
        packages = sorted(set(packages))
        print("ZFS 内核头文件：" + headers)

    run(["env", "DEBIAN_FRONTEND=noninteractive",
         "apt-get", "install", "-y", "--no-install-recommends", *packages],
        check=True, timeout=1800)

    for dep in selected:
        for service in dep["services"]:
            run(["systemctl", "enable", "--now", service], check=False)

    print("安装完成")
    for dep in dependency_status():
        if dep["key"] in keys:
            print(f"  {dep['name']}: {dep['detail']}")


# ---------------------------------------------------------------- zfs

DATASET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*(/[A-Za-z0-9][A-Za-z0-9_.:-]*)*$")
SNAP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def zfs_available() -> bool:
    return shutil.which("zfs") is not None and shutil.which("zpool") is not None


def zfs_pools() -> list[dict]:
    proc = run(["zpool", "list", "-Hp", "-o", "name,size,alloc,free,health,cap,frag"])
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        name, size, alloc, free, health, cap, frag = parts[:7]
        rows.append({
            "name": name,
            "size": int(size) if size.isdigit() else None,
            "alloc": int(alloc) if alloc.isdigit() else None,
            "free": int(free) if free.isdigit() else None,
            "health": health,
            "cap": cap if cap.endswith("%") else cap + "%",
            "frag": frag if frag.endswith("%") else frag + "%",
        })
    return rows


def zfs_datasets() -> list[dict]:
    proc = run(["zfs", "list", "-Hp", "-o", "name,type,used,avail,refer,mountpoint,encryption",
                "-t", "filesystem,volume"])
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        name, dtype, used, avail, refer, mountpoint, encryption = parts[:7]
        rows.append({
            "name": name,
            "type": dtype,
            "used": int(used) if used.isdigit() else None,
            "avail": int(avail) if avail.isdigit() else None,
            "refer": int(refer) if refer.isdigit() else None,
            "mountpoint": "" if mountpoint == "-" else mountpoint,
            "encryption": encryption,
        })
    return rows


def zfs_props(dataset: str, props: list[str]) -> dict:
    proc = run(["zfs", "get", "-H", "-o", "property,value", ",".join(props), dataset],
               check=False)
    if proc.returncode != 0:
        raise NasError(f"读取属性失败: {dataset}")
    result = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            result[parts[0]] = parts[1]
    return result


def zfs_encrypted_datasets() -> list[dict]:
    proc = run(["zfs", "list", "-H", "-o", "name,encryption"], check=False)
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or parts[1] == "off":
            continue
        name = parts[0]
        try:
            info = zfs_props(name, ["keystatus", "keyformat", "keylocation",
                                    "mounted", "mountpoint", "canmount", "type"])
        except NasError:
            continue
        rows.append({"name": name, "encryption": parts[1], **info})
    return rows


def zfs_dataset_exists(name: str) -> bool:
    return run(["zfs", "list", "-H", "-o", "name", name], check=False).returncode == 0


def zfs_snapshots(dataset: str | None = None) -> list[dict]:
    args = ["zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,used,creation", "-s", "creation"]
    if dataset:
        if not zfs_dataset_exists(dataset):
            raise NasError(f"数据集不存在: {dataset}")
        args += ["-r", dataset]
    proc = run(args, check=False)
    if proc.returncode != 0:
        return []
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, used, created = parts[:3]
        dataset_part, _, snap = name.partition("@")
        created_i = int(created) if created.isdigit() else 0
        rows.append({
            "name": name,
            "dataset": dataset_part,
            "snapshot": snap,
            "used": int(used) if used.isdigit() else None,
            "created_text": time.strftime("%Y-%m-%d %H:%M", time.localtime(created_i)) if created_i else "",
        })
    return rows


def _check_dataset_name(name: str) -> str:
    name = name.strip().strip("/")
    if not DATASET_RE.fullmatch(name):
        raise NasError("数据集名称不合法")
    return name


def cmd_zfs_create_dataset(args) -> None:
    need_root()
    parent = _check_dataset_name(args.parent)
    name = _check_dataset_name(args.name)
    if not zfs_dataset_exists(parent):
        raise NasError(f"父数据集不存在: {parent}")
    dataset = f"{parent}/{name}"
    if zfs_dataset_exists(dataset):
        raise NasError(f"数据集已存在: {dataset}")
    encrypted = bool(getattr(args, "encrypted", False))
    passphrase = getattr(args, "passphrase", None)
    parent_encryption = zfs_props(parent, ["encryption"]).get("encryption", "off")
    if parent_encryption != "off" and not encrypted:
        raise NasError("加密数据集下不允许创建未加密子数据集")
    # 新池默认 acltype=off，Samba 权限模型依赖 POSIX ACL
    cmd = ["zfs", "create", "-o", "acltype=posixacl"]
    if args.quota:
        if not ZFS_SIZE_RE.fullmatch(args.quota.strip()):
            raise NasError("配额格式应类似 100G")
        cmd += ["-o", f"quota={args.quota.strip()}"]
    if encrypted:
        if not passphrase or len(passphrase) < 8:
            raise NasError("加密密码至少 8 位")
        cmd += [
            "-o", "encryption=on",
            "-o", "keyformat=passphrase",
            "-o", "keylocation=prompt",
        ]
    cmd.append(dataset)
    run(cmd, input=(f"{passphrase}\n{passphrase}\n" if encrypted else None), check=True)
    if encrypted:
        run(["zfs", "set", "canmount=noauto", dataset], check=True)
    print(f"已创建{'加密' if encrypted else ''}数据集 {dataset}")


def cmd_zfs_destroy_dataset(args) -> None:
    need_root()
    name = _check_dataset_name(args.name)
    if "/" not in name:
        raise NasError("不允许删除存储池根数据集")
    if not zfs_dataset_exists(name):
        raise NasError(f"数据集不存在: {name}")
    zvol_root = f"/dev/zvol/{name}"
    for store in iscsi_storage_all():
        dev = store.get("dev", "")
        if dev == zvol_root or dev.startswith(zvol_root + "/"):
            raise NasError(f"该数据集正被 iSCSI 磁盘使用: {store.get('name')}")

    info = zfs_props(name, ["type", "mountpoint"])
    mountpoint = info.get("mountpoint") or ""
    if info.get("type") == "filesystem" and mountpoint.startswith("/"):
        try:
            blocks = SmbConf(SMB_CONF).load().shares()
        except NasError:
            blocks = []
        for block in blocks:
            if _path_under(block.params().get("path", ""), mountpoint):
                raise NasError(f"该数据集仍有 SMB 共享: {block.name}，请先删除共享")

    cmd = ["zfs", "destroy"]
    if args.recursive:
        cmd.append("-r")
    cmd.append(name)
    run(cmd, check=True)
    if mountpoint.startswith("/"):
        set_immutable(mountpoint, False)
        try:
            Path(mountpoint).rmdir()
        except OSError:
            pass
    print(f"已删除数据集 {name}")


def after_dataset_unlocked() -> None:
    mounted = mount_datasets_for_shares()
    if mounted:
        print("已为 SMB 挂载: " + "、".join(mounted))

    apply_share_locks()
    before_targets, before_stores = iscsi_suspended_summary()
    if shutil.which("targetcli"):
        apply_iscsi_locks()
        after_targets, after_stores = iscsi_suspended_summary()
        restored_t = [name for name in before_targets if name not in after_targets]
        restored_s = [name for name in before_stores if name not in after_stores]
        if restored_t:
            print("已恢复 iSCSI target: " + "、".join(restored_t))
        if restored_s:
            print("已恢复 iSCSI backstore: " + "、".join(restored_s))


def after_dataset_locked() -> None:
    ensure_smb_coherence()
    ensure_share_exec_defaults()
    apply_share_locks()
    if shutil.which("targetcli"):
        hidden_targets, hidden_stores = apply_iscsi_locks()
        if hidden_targets:
            print("已隐藏 iSCSI target: " + "、".join(hidden_targets))
        if hidden_stores:
            print("已隐藏 iSCSI backstore: " + "、".join(hidden_stores))
    if zfs_available():
        try:
            for row in zfs_encrypted_datasets():
                if row.get("type") == "filesystem" and row.get("mounted") != "yes":
                    lock_mountpoint(row)
        except NasError:
            pass


def cmd_zfs_load_key(args) -> None:
    need_root()
    info = zfs_props(args.dataset, ["keystatus", "keylocation", "keyformat"])
    if info.get("keystatus") == "available":
        print(f"密钥已加载: {args.dataset}")
        after_dataset_unlocked()
        return
    text = None
    if info.get("keylocation") == "prompt":
        if not getattr(args, "passphrase", None):
            raise NasError("该数据集需要密码")
        text = args.passphrase + "\n"
    cmd = ["zfs", "load-key"]
    if getattr(args, "recursive", False):
        cmd.append("-r")
    cmd.append(args.dataset)
    run(cmd, input=text, check=True)
    print(f"已加载密钥: {args.dataset}")
    after_dataset_unlocked()


def cmd_zfs_unload_key(args) -> None:
    need_root()
    info = zfs_props(args.dataset, ["keystatus", "mounted"])
    if info.get("keystatus") != "available":
        print(f"密钥未加载: {args.dataset}")
        after_dataset_locked()
        return
    if info.get("mounted") == "yes" and not getattr(args, "force", False):
        raise NasError("数据集已挂载，请先卸载挂载点")
    if getattr(args, "force", False) and info.get("mounted") == "yes":
        run(["zfs", "unmount", "-f", args.dataset], check=True)

    # zvol 被 iSCSI backstore 打开时无法 unload-key，必须先摘掉
    apply_share_locks()
    if shutil.which("targetcli"):
        apply_iscsi_locks(extra_locked=[args.dataset])

    cmd = ["zfs", "unload-key"]
    if getattr(args, "recursive", False):
        cmd.append("-r")
    cmd.append(args.dataset)
    try:
        run(cmd, check=True)
    except NasError:
        # 卸载失败就把临时隐藏的 target 恢复
        if shutil.which("targetcli"):
            apply_iscsi_locks()
        raise
    print(f"已卸载密钥: {args.dataset}")
    after_dataset_locked()


def cmd_zfs_mount(args) -> None:
    need_root()
    info = zfs_props(args.dataset, ["type", "mounted", "keystatus"])
    if info.get("type") != "filesystem":
        raise NasError("zvol 不需要挂载，加载密钥后设备会自动出现")
    if info.get("mounted") == "yes":
        print(f"已挂载: {args.dataset}")
        return
    if info.get("keystatus") not in (None, "-", "available"):
        raise NasError("密钥未加载，无法挂载")
    mount_dataset_safe(args.dataset)
    print(f"已挂载: {args.dataset}")
    apply_share_locks()


def cmd_zfs_unmount(args) -> None:
    need_root()
    info = zfs_props(args.dataset, ["mounted"])
    if info.get("mounted") != "yes":
        print(f"未挂载: {args.dataset}")
        return
    run(["zfs", "unmount", args.dataset], check=True)
    print(f"已卸载挂载点: {args.dataset}")
    after_dataset_locked()


def cmd_zfs_scrub(args) -> None:
    need_root()
    if not any(pool["name"] == args.pool for pool in zfs_pools()):
        raise NasError(f"存储池不存在: {args.pool}")
    run(["zpool", "scrub", args.pool], check=True)
    print(f"已启动 {args.pool} 的 scrub")


def cmd_zfs_snapshot_create(args) -> None:
    need_root()
    dataset = _check_dataset_name(args.dataset)
    if not zfs_dataset_exists(dataset):
        raise NasError(f"数据集不存在: {dataset}")
    name = args.name.strip()
    if not SNAP_RE.fullmatch(name):
        raise NasError("快照名只能包含字母、数字、下划线、点、冒号和短横线")
    full = f"{dataset}@{name}"
    if any(s["name"] == full for s in zfs_snapshots(dataset)):
        raise NasError(f"快照已存在: {full}")
    cmd = ["zfs", "snapshot"]
    if args.recursive:
        cmd.append("-r")
    cmd.append(full)
    run(cmd, check=True)
    print(f"已创建快照 {full}")


def cmd_zfs_snapshot_destroy(args) -> None:
    need_root()
    snapshot = args.snapshot.strip()
    if "@" not in snapshot:
        raise NasError("快照名称应为 dataset@snapshot")
    dataset = snapshot.split("@", 1)[0]
    if not any(s["name"] == snapshot for s in zfs_snapshots(dataset)):
        raise NasError(f"快照不存在: {snapshot}")
    cmd = ["zfs", "destroy"]
    if args.recursive:
        cmd.append("-r")
    cmd.append(snapshot)
    run(cmd, check=True)
    print(f"已删除快照 {snapshot}")


def cmd_zfs_snapshot_rollback(args) -> None:
    need_root()
    snapshot = args.snapshot.strip()
    if "@" not in snapshot:
        raise NasError("快照名称应为 dataset@snapshot")
    dataset = snapshot.split("@", 1)[0]
    if not any(s["name"] == snapshot for s in zfs_snapshots(dataset)):
        raise NasError(f"快照不存在: {snapshot}")
    if args.confirm != snapshot:
        raise NasError("回滚前请完整输入快照名称")
    cmd = ["zfs", "rollback"]
    if args.recursive:
        cmd += ["-r", "-R"]
    cmd.append(snapshot)
    run(cmd, check=True)
    print(f"已回滚到 {snapshot}")


# ------------------------------------------------------------ 自动快照
AUTO_SNAP_DAYS = {
    "Mon": "周一", "Tue": "周二", "Wed": "周三", "Thu": "周四",
    "Fri": "周五", "Sat": "周六", "Sun": "周日",
}


def load_auto_snapshot() -> dict:
    data = _read_json_file(AUTO_SNAP_FILE, {})
    datasets = [str(x).strip() for x in data.get("datasets", []) if str(x).strip()]
    try:
        keep = int(data.get("keep", 7) or 0)
    except (TypeError, ValueError):
        keep = 7
    return {
        "enabled": bool(data.get("enabled", False)),
        "oncalendar": str(data.get("oncalendar") or "*-*-* 03:00:00"),
        "keep": max(0, keep),
        "datasets": datasets,
        "last_run": str(data.get("last_run") or ""),
        "last_result": str(data.get("last_result") or ""),
    }


def save_auto_snapshot(data: dict) -> None:
    _write_json_file(AUTO_SNAP_FILE, data)


def auto_snapshot_schedule_text(spec: str) -> str:
    spec = (spec or "").strip()
    if spec == "*-*-* *:00:00":
        return "每小时整点"
    if spec == "*-*-* 00,06,12,18:00:00":
        return "每 6 小时"
    match = re.fullmatch(r"\*-\*-\* (\d{2}):(\d{2}):00", spec)
    if match:
        return f"每天 {match.group(1)}:{match.group(2)}"
    match = re.fullmatch(
        r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (\d{2}):(\d{2}):00", spec)
    if match:
        return f"每{AUTO_SNAP_DAYS[match.group(1)]} {match.group(2)}:{match.group(3)}"
    return spec or "-"


def _auto_snap_time(value: str) -> str | None:
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", value.strip())
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    return f"{hour:02d}:{minute:02d}"


def auto_snapshot_run() -> int:
    """由 systemd timer 调用：为选中的数据集创建快照并按保留数清理。"""
    if not zfs_available():
        print("zfs 不可用，跳过自动快照")
        return 1
    cfg = load_auto_snapshot()
    if not cfg["enabled"]:
        print("自动快照未启用")
        return 0
    datasets = [name for name in cfg["datasets"] if zfs_dataset_exists(name)]
    if not datasets:
        print("没有可用的数据集")
        return 1

    stamp = time.strftime("%Y%m%d-%H%M%S")
    created = pruned = failed = 0
    for dataset in datasets:
        snapshot = f"{dataset}@{AUTO_SNAP_PREFIX}{stamp}"
        proc = run(["zfs", "snapshot", snapshot], check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()[:200]
            print(f"创建失败 {snapshot}: {detail}")
            failed += 1
            continue
        created += 1
        keep = cfg["keep"]
        if keep <= 0:
            continue
        rows = [row for row in zfs_snapshots(dataset)
                if row["snapshot"].startswith(AUTO_SNAP_PREFIX)]
        for row in rows[:-keep]:
            if run(["zfs", "destroy", row["name"]], check=False).returncode == 0:
                pruned += 1

    cfg["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
    cfg["last_result"] = f"新建 {created}，清理 {pruned}，失败 {failed}"
    save_auto_snapshot(cfg)
    print(f"自动快照 {cfg['last_run']}：{cfg['last_result']}")
    return 0 if failed == 0 else 1


AUTO_SNAP_SERVICE_TEXT = """[Unit]
Description=NAS automatic ZFS snapshots
After=zfs-mount.service
ConditionPathExists={install}

[Service]
Type=oneshot
Environment=NAS_AUTO_SNAPSHOT=1
ExecStart={install}
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=900
"""

AUTO_SNAP_TIMER_TEXT = """[Unit]
Description=NAS automatic ZFS snapshot timer

[Timer]
OnCalendar={schedule}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""


def _write_unit(path: Path, text: str) -> bool:
    changed = True
    try:
        changed = path.read_text(encoding="utf-8") != text
    except OSError:
        pass
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    return changed


def install_auto_snapshot_units(cfg: dict) -> None:
    need_root()
    _write_unit(AUTO_SNAP_UNIT,
                AUTO_SNAP_SERVICE_TEXT.format(install=str(INSTALL_PATH)))
    _write_unit(AUTO_SNAP_TIMER,
                AUTO_SNAP_TIMER_TEXT.format(schedule=cfg["oncalendar"]))
    run(["systemctl", "daemon-reload"], check=True)
    if cfg["enabled"]:
        run(["systemctl", "enable", "--now", "nas-auto-snapshot.timer"], check=True)
    else:
        run(["systemctl", "disable", "--now", "nas-auto-snapshot.timer"], check=False)


def auto_snapshot_timer_state() -> str:
    if not AUTO_SNAP_TIMER.exists():
        return "未安装"
    return _service_state("nas-auto-snapshot.timer")


def ui_auto_snapshot_menu() -> None:
    if not zfs_available():
        print("未安装 ZFS：apt install zfsutils-linux")
        return
    while True:
        cfg = load_auto_snapshot()
        info = [
            f"状态    {'已开启' if cfg['enabled'] else '已关闭'}（定时器 {auto_snapshot_timer_state()}）",
            f"计划    {auto_snapshot_schedule_text(cfg['oncalendar'])}",
            f"保留    {cfg['keep'] or '不清理'} 份自动快照",
            f"数据集  {'、'.join(cfg['datasets']) or '(未选择)'}",
            f"上次    {cfg['last_run'] or '无'}  {cfg['last_result']}",
        ]
        choice = select_one("自动快照", [
            ("关闭自动快照" if cfg["enabled"] else "开启自动快照", "toggle"),
            ("设置计划", "schedule"),
            ("选择数据集", "datasets"),
            ("设置保留份数", "keep"),
            ("立即执行一次", "now"),
            ("返回", "back"),
        ], info=info)
        if choice in (None, "back"):
            return

        if choice == "toggle":
            if not cfg["enabled"]:
                if not cfg["datasets"]:
                    print("请先选择要自动快照的数据集。")
                    continue
                if not ask_confirm("开启后按计划自动创建 ZFS 快照并清理旧快照？", True):
                    continue
            cfg["enabled"] = not cfg["enabled"]
            save_auto_snapshot(cfg)
            install_auto_snapshot_units(cfg)
            print("已开启自动快照" if cfg["enabled"] else "已关闭自动快照")
            pause()

        elif choice == "schedule":
            preset = select_one("快照计划", [
                ("每小时整点", "hourly"),
                ("每 6 小时（00/06/12/18 点）", "six"),
                ("每天指定时间", "daily"),
                ("每周指定时间", "weekly"),
                ("返回", "back"),
            ])
            if preset in (None, "back"):
                continue
            if preset == "hourly":
                cfg["oncalendar"] = "*-*-* *:00:00"
            elif preset == "six":
                cfg["oncalendar"] = "*-*-* 00,06,12,18:00:00"
            else:
                day = ""
                if preset == "weekly":
                    day = select_one("星期", [
                        ("周一", "Mon"), ("周二", "Tue"), ("周三", "Wed"),
                        ("周四", "Thu"), ("周五", "Fri"), ("周六", "Sat"),
                        ("周日", "Sun"), ("返回", "back"),
                    ])
                    if day in (None, "back"):
                        continue
                value = ask_text("时间（HH:MM）", "03:00")
                clock = _auto_snap_time(value)
                if not clock:
                    print("时间格式不正确，应为 HH:MM。")
                    pause()
                    continue
                if day:
                    cfg["oncalendar"] = f"{day} *-*-* {clock}:00"
                else:
                    cfg["oncalendar"] = f"*-*-* {clock}:00"
            save_auto_snapshot(cfg)
            if AUTO_SNAP_TIMER.exists():
                install_auto_snapshot_units(cfg)
            print(f"计划已改为 {auto_snapshot_schedule_text(cfg['oncalendar'])}")
            pause()

        elif choice == "datasets":
            rows = [row for row in zfs_datasets() if row["type"] == "filesystem"]
            if not rows:
                print("没有可用的文件系统数据集。")
                pause()
                continue
            picked = select_multi(
                "选择要自动快照的数据集",
                [(row["name"], row["name"]) for row in rows],
                initial=[name for name in cfg["datasets"]
                         if name in {row["name"] for row in rows}],
                info=["只对选中的数据集创建快照，子数据集不自动包含"],
            )
            if picked is None:
                continue
            cfg["datasets"] = list(picked)
            save_auto_snapshot(cfg)
            print(f"已选择 {len(picked)} 个数据集")
            pause()

        elif choice == "keep":
            value = ask_text("保留份数（0 表示不清理）", str(cfg["keep"]))
            if not value.isdigit():
                print("请输入非负整数。")
                pause()
                continue
            cfg["keep"] = int(value)
            save_auto_snapshot(cfg)
            print(f"保留份数已设为 {cfg['keep'] or '不清理'}")
            pause()

        elif choice == "now":
            if not cfg["datasets"]:
                print("请先选择要自动快照的数据集。")
                pause()
                continue
            auto_snapshot_run()
            pause()


# ---------------------------------------------------------------- disks

POOL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,62}$")
DISK_SKIP_PREFIX = ("loop", "zram", "sr", "dm-", "md", "zd")


def disk_list() -> list[dict]:
    if not shutil.which("lsblk"):
        return []
    proc = run(["lsblk", "-J", "-b", "-d",
                "-o", "NAME,KNAME,PATH,TYPE,SIZE,MODEL,ROTA,TRAN"],
               check=False)
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return []
    rows = []
    for item in data.get("blockdevices", []):
        name = str(item.get("name") or "")
        if item.get("type") != "disk" or not name:
            continue
        if name.startswith(DISK_SKIP_PREFIX):
            continue
        rota = item.get("rota")
        if isinstance(rota, str):
            rotational = rota.lower() not in {"0", "false", "no"}
        else:
            rotational = bool(rota)
        size = item.get("size")
        try:
            size_i = int(size) if size is not None else 0
        except (TypeError, ValueError):
            size_i = 0
        rows.append({
            "name": name,
            "path": str(item.get("path") or f"/dev/{name}"),
            "size": size_i,
            "model": str(item.get("model") or "").strip(),
            "rota": rotational,
            "tran": str(item.get("tran") or "").strip(),
        })
    return sorted(rows, key=lambda row: row["name"])


def disk_pool_map() -> dict[str, str]:
    if not zfs_available() or not shutil.which("lsblk"):
        return {}
    proc = run(["zpool", "status", "-P", "-L"], check=False)
    result: dict[str, str] = {}
    pool = ""
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("pool:"):
            pool = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("/dev/") and pool:
            path = stripped.split()[0]
            real = os.path.realpath(path)
            result[real] = pool
            pk = run(["lsblk", "-no", "PKNAME", real], check=False).stdout.strip()
            if pk:
                result[f"/dev/{pk}"] = pool
    return result


def disk_tree(path: str) -> list[dict]:
    if not shutil.which("lsblk"):
        return []
    proc = run(["lsblk", "-J", "-b", "-o",
                "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT", path], check=False)
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return []
    rows: list[dict] = []

    def walk(items):
        for item in items or []:
            rows.append(item)
            walk(item.get("children") or [])

    walk(data.get("blockdevices", []))
    return rows


def disk_is_free(disk: dict, pool_map: dict[str, str] | None = None) -> bool:
    if pool_map is None:
        pool_map = disk_pool_map()
    if pool_map.get(disk["path"]):
        return False
    rows = disk_tree(disk["path"])
    if not rows:
        return False
    for row in rows:
        if row.get("fstype") or row.get("mountpoint"):
            return False
        if row.get("type") in {"part", "crypt", "lvm"}:
            return False
    return True


def _smart_number(text: str) -> str:
    match = re.search(r"(\d[\d,]*)\s*(?:\(|$)", text)
    return match.group(1).replace(",", "") if match else ""


def smart_info(path: str) -> dict:
    info = {
        "available": shutil.which("smartctl") is not None,
        "health": "未知", "temp": "", "hours": "",
        "error": "", "raw": "",
    }
    if not info["available"]:
        info["error"] = "smartctl 未安装"
        return info
    try:
        proc = run(["smartctl", "-H", "-A", path], check=False, timeout=20)
    except NasError as exc:
        info["health"] = "不可用"
        info["error"] = str(exc)
        return info
    text = (proc.stdout or "") + (proc.stderr or "")
    info["raw"] = text
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "overall-health self-assessment test result" in lower or \
                "smart health status" in lower:
            if ":" in stripped:
                info["health"] = stripped.split(":", 1)[1].strip()
        if "Temperature_Celsius" in stripped or "Airflow_Temperature_Cel" in stripped:
            number = _smart_number(stripped)
            if number:
                info["temp"] = number
        elif stripped.startswith("Temperature:") and "Celsius" in stripped:
            match = re.search(r"(\d+)", stripped)
            if match:
                info["temp"] = match.group(1)
        if "Power_On_Hours" in stripped or "Power On Hours" in stripped:
            number = _smart_number(stripped)
            if number:
                info["hours"] = number
    if re.search(r"SMART support is:\s+Unavailable", text) or \
            "Unable to detect device type" in text or \
            "Unknown USB bridge" in text:
        info["health"] = "不可用"
        if not info["error"]:
            match = re.search(r"SMART support is:\s*(.+)", text)
            info["error"] = match.group(1).strip() if match else "设备不支持 SMART"
    return info


def zpool_importable() -> list[dict]:
    if not zfs_available():
        return []
    proc = run(["zpool", "import"], check=False)
    rows: list[dict] = []
    current = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("pool:"):
            current = {
                "name": stripped.split(":", 1)[1].strip(),
                "state": "",
            }
            rows.append(current)
        elif current is not None and stripped.startswith("state:"):
            current["state"] = stripped.split(":", 1)[1].strip()
    return rows


def disk_detail_lines(disk: dict) -> list[str]:
    pool = disk_pool_map().get(disk["path"], "")
    kind = "HDD" if disk["rota"] else "SSD"
    lines = [
        f"设备 {disk['path']}",
        f"容量 {_size_text(disk['size'])} · {kind}"
        + (f" · {disk['tran']}" if disk["tran"] else ""),
        f"型号 {disk['model'] or '未知'}",
    ]
    if pool:
        lines.append(f"ZFS 池 {pool}")
    else:
        lines.append("ZFS 池 未使用")
    children = disk_tree(disk["path"])
    if len(children) > 1:
        for row in children[1:]:
            size = row.get("size")
            try:
                size_text = _size_text(int(size)) if size is not None else "?"
            except (TypeError, ValueError):
                size_text = "?"
            lines.append(
                f"分区 {row.get('name', '?')}  {size_text}  "
                f"{row.get('fstype') or '无文件系统'}  "
                f"{row.get('mountpoint') or ''}"
            )
    if shutil.which("smartctl"):
        info = smart_info(disk["path"])
        if info["health"] == "不可用":
            lines.append(f"SMART 不可用（{info['error'] or '设备不支持'}）")
        else:
            temp = f" · 温度 {info['temp']}°C" if info["temp"] else ""
            hours = f" · 通电 {info['hours']} 小时" if info["hours"] else ""
            lines.append(f"SMART {info['health']}{temp}{hours}")
    else:
        lines.append("SMART 未安装 smartctl")
    return lines


def load_hdd_sleep() -> dict[str, dict]:
    try:
        data = json.loads(HDD_SLEEP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[str(value.get("name") or key)] = value
    return result


def save_hdd_sleep(data: dict[str, dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = HDD_SLEEP_FILE.with_name(HDD_SLEEP_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, HDD_SLEEP_FILE)


def hdd_sleep_key(disk: dict) -> str:
    return disk.get("name") or disk.get("path")


def hdd_sleep_value(minutes: int) -> str:
    if minutes <= 0:
        return "0"
    if minutes <= 20:
        return str(minutes * 12)
    if minutes <= 330:
        return str(240 + max(1, minutes // 30))
    raise NasError("休眠时间最长 330 分钟")


def hdd_power_code(path: str) -> str:
    if not shutil.which("hdparm"):
        return "missing"
    proc = run(["hdparm", "-C", path], check=False, timeout=10)
    text = (proc.stdout or "") + (proc.stderr or "")
    lower = text.lower()
    if "standby" in lower:
        return "standby"
    if "sleeping" in lower:
        return "sleeping"
    if "active/idle" in lower or "active" in lower:
        return "active"
    return "unknown"


def hdd_power_state(path: str) -> str:
    return {
        "missing": "未安装 hdparm",
        "standby": "已休眠",
        "sleeping": "休眠中",
        "active": "活动",
    }.get(hdd_power_code(path), "未知")


def load_hdd_status() -> dict[str, dict]:
    try:
        data = json.loads(HDD_STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(v.get("name") or k): v
        for k, v in data.items() if isinstance(v, dict)
    }


def save_hdd_status(data: dict[str, dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = HDD_STATUS_FILE.with_name(HDD_STATUS_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, HDD_STATUS_FILE)


def load_hdd_alerts() -> dict[str, dict]:
    try:
        data = json.loads(HDD_ALERT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(v.get("name") or k): v
        for k, v in data.items() if isinstance(v, dict)
    }


def save_hdd_alerts(data: dict[str, dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = HDD_ALERT_FILE.with_name(HDD_ALERT_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, HDD_ALERT_FILE)


def _default_server_name() -> str:
    name = os.uname().nodename.strip()
    return name or "nas"


def default_push_config() -> dict:
    return {
        "enabled": False,
        "url": PUSH_DEFAULT_URL,
        "server_name": _default_server_name(),
        "topic": PUSH_DEFAULT_TOPIC,
        "push_to_mqtt": True,
    }


def load_push_config() -> dict:
    config = default_push_config()
    try:
        data = json.loads(PUSH_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return config
    if not isinstance(data, dict):
        return config
    if "enabled" in data:
        config["enabled"] = bool(data.get("enabled"))
    url = data.get("url")
    if isinstance(url, str) and url.strip().startswith(("http://", "https://")):
        config["url"] = url.strip()
    name = data.get("server_name")
    if isinstance(name, str) and name.strip():
        config["server_name"] = name.strip()
    topic = data.get("topic")
    if isinstance(topic, str) and topic.strip():
        config["topic"] = topic.strip()
    if "push_to_mqtt" in data:
        config["push_to_mqtt"] = bool(data.get("push_to_mqtt"))
    return config


def save_push_config(config: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PUSH_FILE.with_name(PUSH_FILE.name + ".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, PUSH_FILE)


def push_message(title: str, message: str, status: str = "info",
                 *, config: dict | None = None, mode: str = "append") -> bool:
    config = config or load_push_config()
    payload = {
        "server_name": config["server_name"],
        "category": "service",
        "topic": config["topic"],
        "title": title,
        "message": message,
        "status": status,
        "push_to_mqtt": bool(config["push_to_mqtt"]),
        "msg_type": "markdown",
        "mode": mode if mode in {"append", "overwrite"} else "append",
    }
    request = urllib.request.Request(
        config["url"],
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=PUSH_TIMEOUT) as response:
            response.read(4096)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        detail = str(exc)
        if isinstance(exc, urllib.error.HTTPError):
            try:
                detail = f"{exc.code} {exc.read(500).decode('utf-8', 'replace')}"
            except OSError:
                detail = f"{exc.code} {exc.reason}"
        print(f"推送失败（{title}）: {detail}", file=sys.stderr, flush=True)
        return False
    return True


def notify_hdd_event(disk: dict, event: str, minutes: int, note: str = "") -> None:
    config = load_push_config()
    if not config["enabled"]:
        return
    try:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if event == "sleep":
            title = f"硬盘 {disk['name']} 已休眠"
            state = "已休眠"
            status = "ok"
        else:
            title = f"硬盘 {disk['name']} 被唤醒"
            state = "活动"
            status = "warn" if note else "info"
        lines = [
            f"- 设备：`{disk['path']}`",
            f"- 型号：{disk.get('model') or '未知'}",
            f"- ZFS 池：{disk.get('pool') or '未使用'}",
            f"- 当前状态：{state}",
            f"- 空闲休眠：{minutes} 分钟" if minutes > 0 else "- 空闲休眠：未设置",
            f"- 时间：{stamp}",
        ]
        if note:
            lines.append(f"- 处理：{note}")
        push_message(title, "\n".join(lines), status, config=config)
    except Exception as exc:  # 推送失败不能影响监控
        print(f"推送异常（{disk['name']} {event}）: {exc}",
              file=sys.stderr, flush=True)


def disable_hdd_sleep(disk: dict, reason: str, minutes: int, wakes: int) -> None:
    key = hdd_sleep_key(disk)
    settings = load_hdd_sleep()
    settings.pop(key, None)
    save_hdd_sleep(settings)
    alerts = load_hdd_alerts()
    alerts[key] = {
        "name": disk["name"], "path": disk["path"], "model": disk["model"],
        "time": time.time(), "reason": reason,
        "minutes": minutes, "wakes": wakes,
    }
    save_hdd_alerts(alerts)
    run(["hdparm", "-S", "0", disk["path"]], check=False, timeout=20)
    print(f"{disk['name']} 异常唤醒，已取消休眠并保持常转: {reason}", flush=True)


def hdd_monitor() -> int:
    try:
        interval = max(10, int(os.environ.get("NAS_HDD_MONITOR_INTERVAL", "60")))
    except ValueError:
        interval = 60
    if not load_hdd_sleep() and not space_monitor_needed():
        print("nas-hdd-monitor: 没有配置休眠或空间监控，退出", flush=True)
        return 0
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    monitor_lock = open(MONITOR_LOCK_FILE, "w")
    try:
        fcntl.flock(monitor_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("nas-hdd-monitor: 已有监控进程，退出", flush=True)
        monitor_lock.close()
        return 0
    previous = load_hdd_status()
    print(f"nas-hdd-monitor: 启动，间隔 {interval}s", flush=True)
    while True:
        if not load_hdd_sleep() and not space_monitor_needed():
            print("nas-hdd-monitor: 没有配置休眠或空间监控，退出", flush=True)
            return 0
        current: dict[str, dict] = {}
        now = time.time()
        settings = load_hdd_sleep()
        try:
            disks = disk_list()
            pool_map = disk_pool_map()
        except NasError as exc:
            print(f"读取磁盘列表失败: {exc}", flush=True)
            time.sleep(interval)
            continue
        for disk in disks:
            if not disk.get("rota"):
                continue
            key = hdd_sleep_key(disk)
            pool = pool_map.get(disk["path"], "")
            try:
                code = hdd_power_code(disk["path"])
            except NasError as exc:
                print(f"{disk['name']} 状态检查失败: {exc}", flush=True)
                code = "unknown"
            old = previous.get(key, {})
            history = list(old.get("history") or [])[-50:]
            old_power = old.get("power")
            event = None
            if old_power in {"standby", "sleeping"} and code == "active":
                event = "wake"
                print(f"{disk['name']} 从休眠唤醒", flush=True)
            elif old_power == "active" and code in {"standby", "sleeping"}:
                event = "sleep"
                print(f"{disk['name']} 进入{('休眠' if code == 'standby' else '深度休眠')}", flush=True)
            elif old_power and old_power != code and code not in {"unknown", "missing"}:
                print(f"{disk['name']} 状态 {old_power} -> {code}", flush=True)
            if event:
                history.append({"time": now, "event": event})
                history = history[-50:]

            value = settings.get(key, {})
            try:
                minutes = int(value.get("minutes", 0) or 0)
            except (TypeError, ValueError):
                minutes = 0
            wake_note = ""
            if event == "wake" and minutes > 0:
                try:
                    armed = float(value.get("armed_at", 0) or 0)
                except (TypeError, ValueError):
                    armed = 0
                cutoff = max(now - 2 * 86400, armed)
                wakes = sum(
                    1 for item in history
                    if item.get("event") == "wake" and item.get("time", 0) >= cutoff
                )
                sleep_times = [
                    item.get("time", 0) for item in history
                    if item.get("event") == "sleep" and item.get("time", 0) >= armed
                ]
                last_sleep = max(sleep_times) if sleep_times else 0
                reason = None
                if last_sleep and now - last_sleep <= minutes * 60 + interval:
                    reason = (
                        f"休眠后 {int((now - last_sleep) / 60)} 分钟内被唤醒"
                        f"（设置 {minutes} 分钟）"
                    )
                elif wakes >= 3:
                    reason = f"2 天内被唤醒 {wakes} 次"
                if reason:
                    disable_hdd_sleep(disk, reason, minutes, wakes)
                    settings.pop(key, None)
                    wake_note = f"{reason}，已取消休眠并保持常转"
            if event and minutes > 0:
                event_disk = dict(disk)
                event_disk["pool"] = pool
                notify_hdd_event(event_disk, event, minutes, wake_note)

            changed = old.get("since") if old_power == code else now
            current[key] = {
                "name": disk["name"],
                "path": disk["path"],
                "model": disk["model"],
                "pool": pool,
                "power": code,
                "state": {
                    "standby": "已休眠", "sleeping": "休眠中",
                    "active": "活动", "unknown": "未知",
                    "missing": "未安装 hdparm",
                }.get(code, "未知"),
                "since": changed,
                "updated": now,
                "history": history,
            }
        save_hdd_status(current)
        previous = current
        check_space_alerts()
        time.sleep(interval)


def apply_hdd_sleep_settings() -> None:
    if not shutil.which("hdparm"):
        print("hdparm 未安装，跳过硬盘休眠设置")
        return
    settings = load_hdd_sleep()
    alerts = load_hdd_alerts()
    if not settings and not alerts:
        return
    disks = disk_list()
    by_name = {disk["name"]: disk for disk in disks}
    for key, value in alerts.items():
        disk = by_name.get(key) or by_name.get(str(value.get("name") or ""))
        if disk is not None:
            run(["hdparm", "-S", "0", disk["path"]], check=False, timeout=20)
    for key, value in settings.items():
        disk = by_name.get(key) or by_name.get(str(value.get("name") or ""))
        if disk is None:
            continue
        try:
            minutes = int(value.get("minutes", 0))
        except (TypeError, ValueError):
            continue
        if minutes <= 0:
            continue
        proc = run(["hdparm", "-S", hdd_sleep_value(minutes), disk["path"]],
                   check=False, timeout=20)
        if proc.returncode != 0:
            print(f"设置 {disk['path']} 休眠失败: "
                  f"{(proc.stderr or proc.stdout).strip()[:200]}")


SYSTEM_SPACE_KEY = "/"
SYSTEM_SPACE_LABEL = "系统盘"


def load_space_config() -> dict:
    config = {"enabled": False, "thresholds": {}, "system_threshold": 10}
    try:
        data = json.loads(SPACE_MONITOR_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return config
    if not isinstance(data, dict):
        return config
    config["enabled"] = bool(data.get("enabled"))
    thresholds = data.get("thresholds")
    if isinstance(thresholds, dict):
        for name, value in thresholds.items():
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= number <= 99:
                config["thresholds"][str(name)] = number
    try:
        system_number = int(data.get("system_threshold", 10))
    except (TypeError, ValueError):
        system_number = 10
    if 0 <= system_number <= 99:
        config["system_threshold"] = system_number
    return config


def save_space_config(config: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SPACE_MONITOR_FILE.with_name(SPACE_MONITOR_FILE.name + ".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, SPACE_MONITOR_FILE)


def space_usage_text(row: dict) -> str:
    return (f"{_size_text(row['free'])} / {_size_text(row['size'])}"
            f"（{row['percent']:.1f}%）")


def space_threshold(config: dict, target: str) -> int:
    if target == SYSTEM_SPACE_KEY:
        raw = config.get("system_threshold", 10)
    else:
        raw = config.get("thresholds", {}).get(target, 10)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 10
    return value if 0 <= value <= 99 else 10


def space_alert_label(key: str) -> str:
    return SYSTEM_SPACE_LABEL if key == SYSTEM_SPACE_KEY else key


def load_space_alerts() -> dict[str, dict]:
    try:
        data = json.loads(SPACE_ALERT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def save_space_alerts(data: dict[str, dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SPACE_ALERT_FILE.with_name(SPACE_ALERT_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, SPACE_ALERT_FILE)


def pool_space_rows() -> list[dict]:
    if not zfs_available():
        return []
    proc = run(["zpool", "list", "-Hp", "-o", "name,size,free,health"], check=False)
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, size, free, health = parts[:4]
        if not size.isdigit() or not free.isdigit():
            continue
        mounted = run(["zfs", "get", "-H", "-o", "value", "mounted", name],
                      check=False).stdout.strip()
        if mounted != "yes":
            continue
        size_i, free_i = int(size), int(free)
        percent = (free_i / size_i * 100) if size_i else 0.0
        rows.append({
            "name": name, "size": size_i, "free": free_i,
            "percent": percent, "health": health, "mounted": mounted,
        })
    return rows


def system_space_row() -> dict | None:
    try:
        stats = os.statvfs(SYSTEM_SPACE_KEY)
    except OSError:
        return None
    size = stats.f_blocks * stats.f_frsize
    free = stats.f_bavail * stats.f_frsize
    if size <= 0:
        return None
    fstype = run(["stat", "-f", "-c", "%T", SYSTEM_SPACE_KEY],
                 check=False).stdout.strip() or "-"
    return {
        "name": SYSTEM_SPACE_KEY, "label": SYSTEM_SPACE_LABEL,
        "mount": SYSTEM_SPACE_KEY, "size": size, "free": free,
        "percent": free / size * 100, "fstype": fstype, "kind": "system",
    }


def space_targets() -> list[dict]:
    targets: list[dict] = []
    system = system_space_row()
    if system:
        targets.append(system)
    for row in pool_space_rows():
        item = dict(row)
        item["label"] = f"ZFS 池 {row['name']}"
        item["kind"] = "pool"
        targets.append(item)
    return targets


def check_space_alerts() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    handle = open(SPACE_LOCK_FILE, "w")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        _check_space_alerts_locked()
    finally:
        handle.close()


def _space_alert_detail(target: dict, threshold: int, stamp: str) -> str:
    if target["kind"] == "system":
        return (
            f"- 分区：{target['mount']}\n"
            f"- 文件系统：{target.get('fstype') or '-'}\n"
            f"- 剩余：{space_usage_text(target)}\n"
            f"- 阈值：低于 {threshold}%\n"
            f"- 时间：{stamp}"
        )
    return (
        f"- 池：{target['name']}\n"
        f"- 剩余：{space_usage_text(target)}\n"
        f"- 阈值：低于 {threshold}%\n"
        f"- 健康：{target.get('health') or '-'}\n"
        f"- 时间：{stamp}"
    )


def _check_space_alerts_locked() -> None:
    config = load_space_config()
    if not config["enabled"]:
        if load_space_alerts():
            save_space_alerts({})
        return
    targets = space_targets()
    alerts = load_space_alerts()
    push_config = load_push_config()
    now = time.time()
    changed = False
    current_keys = {target["name"] for target in targets}

    for target in targets:
        key = target["name"]
        label = target["label"]
        threshold = space_threshold(config, key)
        if threshold <= 0:
            if key in alerts:
                alerts.pop(key, None)
                changed = True
            continue
        low = target["percent"] < threshold
        old = alerts.get(key)
        if low:
            if (not old or not old.get("low")
                    or now - float(old.get("time", 0)) >= SPACE_REALERT_SECONDS):
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                title = f"{label} 空间不足"
                detail = _space_alert_detail(target, threshold, stamp)
                if push_config["enabled"]:
                    push_message(title, detail, "warn", config=push_config,
                                 mode="overwrite")
                else:
                    print(f"{title}（推送未开启）: {target['percent']:.1f}% < {threshold}%",
                          flush=True)
                alerts[key] = {
                    "low": True, "time": now, "free": target["free"],
                    "size": target["size"], "percent": target["percent"],
                    "threshold": threshold, "label": label,
                    "kind": target["kind"],
                }
                if target["kind"] == "system":
                    alerts[key]["mount"] = target["mount"]
                else:
                    alerts[key]["health"] = target.get("health")
                changed = True
        elif old and old.get("low"):
            if push_config["enabled"]:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                if target["kind"] == "system":
                    head = (f"- 分区：{target['mount']}\n"
                            f"- 文件系统：{target.get('fstype') or '-'}")
                else:
                    head = f"- 池：{key}"
                push_message(
                    f"{label} 空间已恢复",
                    f"{head}\n- 剩余：{space_usage_text(target)}\n"
                    f"- 阈值：{threshold}%\n- 时间：{stamp}",
                    "ok", config=push_config, mode="overwrite",
                )
            alerts.pop(key, None)
            changed = True

    for key in list(alerts):
        if key not in current_keys:
            alerts.pop(key, None)
            changed = True
    if changed:
        save_space_alerts(alerts)


def space_monitor_needed() -> bool:
    return bool(load_space_config().get("enabled"))


# ---------------------------------------------------------------- tui


class NS:
    """给 cmd_* 函数用的轻量命名空间。"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _read_key(fd: int) -> str:
    data = os.read(fd, 1)
    if not data:
        return "cancel"
    char = data.decode("utf-8", "ignore")
    if char == "\x1b":
        seq = b""
        while select.select([fd], [], [], 0.3)[0]:
            seq += os.read(fd, 1)
            if len(seq) >= 2:
                break
        if seq[:1] == b"[":
            return {
                b"A": "up", b"B": "down", b"C": "right", b"D": "left",
                b"H": "home", b"F": "end",
            }.get(seq[1:2], "other")
        return "cancel"
    if char == " ":
        return "space"
    if char in ("\r", "\n"):
        return "enter"
    if char in ("q", "Q", "\x03"):
        return "cancel"
    return char


def _viewport(index: int, total: int, extra: int = 0) -> tuple[int, int]:
    rows = max(5, shutil.get_terminal_size((80, 24)).lines - 8 - extra)
    if total <= rows:
        return 0, total
    start = max(0, min(index - rows // 2, total - rows))
    return start, start + rows


def _select_one_raw(title: str, options: list[tuple[str, object]], default: int = 0,
               info: list[str] | None = None):
    """方向键选择；info 会显示在标题下方。"""
    if not options:
        return None
    info_lines = list(info or [])
    index = max(0, min(default, len(options) - 1))
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        sys.stdout.write("\033[?25l")
        while True:
            start, end = _viewport(index, len(options), len(info_lines))
            out = ["\033[H\033[2J", f"\033[1m{title}\033[0m"]
            for line in info_lines:
                out.append(f"\033[2m  {line}\033[0m")
            out.append("")
            if start > 0:
                out.append("   …")
            for i in range(start, end):
                label = options[i][0]
                if i == index:
                    out.append(f"\033[7m ▶ {label}\033[0m")
                else:
                    out.append(f"   {label}")
            if end < len(options):
                out.append("   …")
            out.append("")
            out.append("\033[2m↑/↓ 选择   Enter 确认   q 返回\033[0m")
            sys.stdout.write("\n".join(out) + "\n")
            sys.stdout.flush()

            key = _read_key(fd)
            if key == "up":
                index = (index - 1) % len(options)
            elif key == "down":
                index = (index + 1) % len(options)
            elif key == "home":
                index = 0
            elif key == "end":
                index = len(options) - 1
            elif key == "enter":
                return options[index][1]
            elif key == "cancel":
                return None
    except KeyboardInterrupt:
        return None
    finally:
        sys.stdout.write("\033[?25h\033[H\033[2J")
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _select_multi_raw(title: str, options: list[tuple[str, object]], initial=None,
                 info: list[str] | None = None):
    """空格切换勾选，Enter 确认；返回选中的 value 列表，q/Esc 返回 None。"""
    if not options:
        return None
    info_lines = list(info or [])
    selected = set(initial or [])
    index = 0
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        sys.stdout.write("\033[?25l")
        while True:
            start, end = _viewport(index, len(options), len(info_lines))
            out = ["\033[H\033[2J", f"\033[1m{title}\033[0m"]
            for line in info_lines:
                out.append(f"\033[2m  {line}\033[0m")
            out.append("")
            if start > 0:
                out.append("   …")
            for i in range(start, end):
                label, value = options[i]
                mark = "x" if value in selected else " "
                cursor = "▶" if i == index else " "
                line = f"{cursor} [{mark}] {label}"
                out.append(f"\033[7m{line}\033[0m" if i == index else f" {line}")
            if end < len(options):
                out.append("   …")
            out.append("")
            out.append("\033[2m空格 切换   Enter 确认   q 返回\033[0m")
            sys.stdout.write("\n".join(out) + "\n")
            sys.stdout.flush()

            key = _read_key(fd)
            if key == "up":
                index = (index - 1) % len(options)
            elif key == "down":
                index = (index + 1) % len(options)
            elif key == "space":
                value = options[index][1]
                if value in selected:
                    selected.discard(value)
                else:
                    selected.add(value)
            elif key == "enter":
                return [value for _, value in options if value in selected]
            elif key == "cancel":
                return None
    except KeyboardInterrupt:
        return None
    finally:
        sys.stdout.write("\033[?25h\033[H\033[2J")
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _read_line_raw(prompt: str) -> str:
    """规范模式读取一行，避免 input() 的预读把方向键/后续按键吞掉。"""
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        new = termios.tcgetattr(fd)
        new[3] |= termios.ICANON | termios.ECHO | termios.ISIG
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        buf = b""
        while True:
            ch = os.read(fd, 1)
            if not ch:
                break
            if ch in (b"\n", b"\r"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                break
            buf += ch
        return buf.decode("utf-8", "replace").strip()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _read_secret_raw(prompt: str) -> str:
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        new = termios.tcgetattr(fd)
        new[3] |= termios.ICANON | termios.ISIG
        new[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        buf = b""
        while True:
            ch = os.read(fd, 1)
            if not ch or ch in (b"\n", b"\r"):
                break
            buf += ch
        sys.stdout.write("\n")
        sys.stdout.flush()
        return buf.decode("utf-8", "replace")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def ask_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = read_line(f"{prompt}{suffix}: ")
    return raw or default


def ask_optional(prompt: str) -> str | None:
    raw = read_line(f"{prompt}（回车保留）: ")
    return raw or None


def ask_confirm(title: str, default: bool = True) -> bool | None:
    options = [("是", True), ("否", False)] if default else [("否", False), ("是", True)]
    value = select_one(title, options)
    return value


def ask_keep_bool(title: str, current: bool):
    options = [
        (f"保留（{'是' if current else '否'}）", "keep"),
        ("是", True),
        ("否", False),
    ]
    return select_one(title, options)


def _pause_raw() -> None:
    read_line("\n按 Enter 返回…")


# ---------------------------------------------------------------- 交互界面
_UI_SCREEN = None
_OUT_BUF: list[str] = []
_INFO_CACHE = {"ts": 0.0, "lines": []}


class _BufferedOut:
    """交互模式下的 stdout：把 print 收进缓冲区，稍后用分页视图展示。"""

    encoding = "utf-8"

    def write(self, text):
        if not isinstance(text, str):
            text = str(text)
        _OUT_BUF.append(text)
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return True

    def fileno(self):
        return sys.__stdout__.fileno()


def _ui_w(s) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in str(s))


def _ui_trunc(s, cells: int) -> str:
    out = []
    used = 0
    for ch in str(s):
        cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if used + cw > cells:
            break
        out.append(ch)
        used += cw
    return "".join(out)


def _ui_pad(s, width: int) -> str:
    s = str(s)
    return s + " " * max(0, width - _ui_w(s))


def _ui_add(scr, y, x, text, attr=0) -> None:
    """按显示宽度截断后再写入，避免中文撑到最后一格导致整屏滚动。"""
    try:
        h, w = scr.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        avail = max(0, w - x - 1)
        out = []
        used = 0
        for ch in str(text):
            cw = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
            if used + cw > avail:
                break
            out.append(ch)
            used += cw
        scr.addstr(y, x, "".join(out), attr)
    except Exception:
        pass


def _ui_box(scr, y, x, h, w, title="", attr=0) -> None:
    if h < 2 or w < 4:
        return
    _ui_add(scr, y, x, "┌" + "─" * (w - 2) + "┐")
    for i in range(1, h - 1):
        _ui_add(scr, y + i, x, "│")
        _ui_add(scr, y + i, x + w - 1, "│")
    _ui_add(scr, y + h - 1, x, "└" + "─" * (w - 2) + "┘")
    if title:
        _ui_add(scr, y, x + 2, f" {title} ", attr | curses.A_BOLD)


def _ui_key(scr):
    try:
        return scr.get_wch()
    except AttributeError:
        return scr.getch()
    except curses.error:
        return None


def _ui_setup(scr) -> None:
    scr.keypad(True)
    try:
        curses.curs_set(0)
    except Exception:
        pass
    if curses.has_colors():
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_YELLOW, -1)
        except Exception:
            pass


def _ui_color(pair: int):
    if curses.has_colors():
        try:
            return curses.color_pair(pair)
        except Exception:
            return 0
    return 0


def _flush_output() -> None:
    """把缓冲区里的输出用分页视图展示出来。"""
    if not _OUT_BUF or _UI_SCREEN is None:
        return
    text = "".join(_OUT_BUF)
    _OUT_BUF.clear()
    if not text.strip():
        return
    _ui_pager("输出", text)


def _ui_pager(title, text) -> None:
    scr = _UI_SCREEN
    lines = str(text).rstrip("\n").split("\n") or [""]
    top = 0
    while True:
        h, w = scr.getmaxyx()
        scr.clear()
        _ui_box(scr, 0, 0, h, w, title)
        body = max(1, h - 4)
        for i, ln in enumerate(lines[top: top + body]):
            _ui_add(scr, 2 + i, 2, ln)
        more = "  ↑/↓ 滚动  PgUp/PgDn 翻页  Enter/q 返回 "
        if top + body < len(lines):
            more = f" [{top + body}/{len(lines)}] " + more
        _ui_add(scr, h - 1, 2, more, curses.A_DIM)
        scr.refresh()
        ch = _ui_key(scr)
        if isinstance(ch, int):
            if ch == curses.KEY_UP:
                top = max(0, top - 1)
            elif ch == curses.KEY_DOWN:
                top = min(max(0, len(lines) - body), top + 1)
            elif ch == curses.KEY_PPAGE:
                top = max(0, top - body)
            elif ch == curses.KEY_NPAGE:
                top = min(max(0, len(lines) - body), top + body)
            elif ch == curses.KEY_HOME:
                top = 0
            elif ch == curses.KEY_END:
                top = max(0, len(lines) - body)
            elif ch in (10, 13, 27, curses.KEY_ENTER):
                return
        elif ch in ("q", "\x1b", "\n", "\r"):
            return


def _ui_msg(title, text, wait="按任意键返回") -> None:
    scr = _UI_SCREEN
    lines = str(text).rstrip("\n").split("\n")
    while True:
        h, w = scr.getmaxyx()
        bw = min(w - 4, max(40, max([_ui_w(x) for x in lines] + [_ui_w(title)]) + 8))
        bh = min(h - 2, len(lines) + 4)
        y0 = max(0, (h - bh) // 2)
        x0 = max(0, (w - bw) // 2)
        scr.clear()
        _ui_box(scr, y0, x0, bh, bw, title)
        for i, ln in enumerate(lines[: bh - 3]):
            _ui_add(scr, y0 + 2 + i, x0 + 2, ln)
        _ui_add(scr, y0 + bh - 1, x0 + 2, f" {wait} ")
        scr.refresh()
        ch = _ui_key(scr)
        if ch is not None:
            return


def _ui_choice(title, options, default=0, info=None):
    """圈选一个选项，返回索引；q/Esc 返回 None。"""
    scr = _UI_SCREEN
    if not options:
        return None
    info = list(info or [])
    pos = min(max(default, 0), len(options) - 1)

    def max_rows(h):
        return max(3, h - 9 - len(info))

    while True:
        h, w = scr.getmaxyx()
        rows = max_rows(h)
        start = max(0, min(pos - rows // 2, len(options) - rows))
        visible = options[start:start + rows]
        bw = min(w - 4, max(40, max([_ui_w(o) for o in options]
                                   + [_ui_w(title)] + [_ui_w(x) for x in info]) + 10))
        bh = min(h - 2, len(info) + len(visible) + 5)
        y0 = max(0, (h - bh) // 2)
        x0 = max(0, (w - bw) // 2)
        scr.clear()
        _ui_box(scr, y0, x0, bh, bw, title)
        y = y0 + 1
        for line in info:
            if y >= y0 + bh - 3:
                break
            _ui_add(scr, y, x0 + 2, "  " + _ui_trunc(line, bw - 4), curses.A_DIM)
            y += 1
        if info:
            y += 1
        for i, opt in enumerate(visible):
            real = start + i
            attr = curses.A_REVERSE if real == pos else 0
            _ui_add(scr, y, x0 + 2,
                    " " + _ui_pad(_ui_trunc(opt, bw - 6), bw - 6) + " ", attr)
            y += 1
        if start > 0:
            _ui_add(scr, y0 + 1, x0 + bw - 3, "…")
        if start + rows < len(options):
            _ui_add(scr, y0 + bh - 2, x0 + bw - 3, "…")
        footer = ("↑/↓ 选择  Enter 确认  q 取消"
                  if len(options) <= rows else
                  f"{pos + 1}/{len(options)}  ↑/↓ 选择  Enter 确认  q 取消")
        _ui_add(scr, y0 + bh - 1, x0 + 2, " " + _ui_trunc(footer, bw - 4) + " ")
        scr.refresh()
        ch = _ui_key(scr)
        if isinstance(ch, int):
            if ch == curses.KEY_UP:
                pos = (pos - 1) % len(options)
            elif ch == curses.KEY_DOWN:
                pos = (pos + 1) % len(options)
            elif ch == curses.KEY_HOME:
                pos = 0
            elif ch == curses.KEY_END:
                pos = len(options) - 1
            elif ch in (10, 13, curses.KEY_ENTER):
                return pos
            elif ch in (27, ord("q")):
                return None
        elif ch in ("k", "j"):
            pos = (pos + (-1 if ch == "k" else 1)) % len(options)
        elif ch in ("\n", "\r"):
            return pos
        elif ch in ("q", "\x1b"):
            return None


def _ui_multi(title, options, initial=None, info=None) -> list:
    """空格勾选，Enter 确认；返回选中的 value 列表，q/Esc 返回 None。"""
    scr = _UI_SCREEN
    if not options:
        return None
    info = list(info or [])
    chosen = set(initial or [])
    pos = 0
    while True:
        h, w = scr.getmaxyx()
        rows = max(3, h - 9 - len(info))
        start = max(0, min(pos - rows // 2, len(options) - rows))
        visible = options[start:start + rows]
        bw = min(w - 4, max(40, max([_ui_w(o[0]) for o in options]
                                   + [_ui_w(title)] + [_ui_w(x) for x in info]) + 14))
        bh = min(h - 2, len(info) + len(visible) + 5)
        y0 = max(0, (h - bh) // 2)
        x0 = max(0, (w - bw) // 2)
        scr.clear()
        _ui_box(scr, y0, x0, bh, bw, title)
        y = y0 + 1
        for line in info:
            if y >= y0 + bh - 3:
                break
            _ui_add(scr, y, x0 + 2, "  " + _ui_trunc(line, bw - 4), curses.A_DIM)
            y += 1
        if info:
            y += 1
        for i, (label, value) in enumerate(visible):
            real = start + i
            mark = "x" if value in chosen else " "
            text = f"[{mark}] {label}"
            attr = curses.A_REVERSE if real == pos else 0
            _ui_add(scr, y, x0 + 2,
                    " " + _ui_pad(_ui_trunc(text, bw - 6), bw - 6) + " ", attr)
            y += 1
        footer = f"{pos + 1}/{len(options)}  空格 切换  Enter 确认  q 取消" \
            if len(options) > rows else "空格 切换  Enter 确认  q 取消"
        _ui_add(scr, y0 + bh - 1, x0 + 2, " " + _ui_trunc(footer, bw - 4) + " ")
        scr.refresh()
        ch = _ui_key(scr)
        if isinstance(ch, int):
            if ch == curses.KEY_UP:
                pos = (pos - 1) % len(options)
            elif ch == curses.KEY_DOWN:
                pos = (pos + 1) % len(options)
            elif ch in (10, 13, curses.KEY_ENTER):
                return [v for _, v in options if v in chosen]
            elif ch in (27, ord("q")):
                return None
        elif ch == " ":
            value = options[pos][1]
            chosen.symmetric_difference_update({value})
        elif ch in ("k", "j"):
            pos = (pos + (-1 if ch == "k" else 1)) % len(options)
        elif ch in ("\n", "\r"):
            return [v for _, v in options if v in chosen]
        elif ch in ("q", "\x1b"):
            return None


def _ui_input(title, default="", hint="", secret=False):
    scr = _UI_SCREEN
    buf = str(default)
    pos = len(buf)
    while True:
        h, w = scr.getmaxyx()
        bw = min(w - 4, max(48, _ui_w(buf) + 10))
        bh = 6
        y0 = max(0, (h - bh) // 2)
        x0 = max(0, (w - bw) // 2)
        scr.clear()
        _ui_box(scr, y0, x0, bh, bw, title)
        if hint:
            _ui_add(scr, y0 + 1, x0 + 2, hint, curses.A_DIM)
        shown = "*" * len(buf) if secret else buf
        _ui_add(scr, y0 + 3, x0 + 2, shown[: bw - 4])
        try:
            curses.curs_set(1)
            scr.move(y0 + 3, min(x0 + 2 + (_ui_w(buf[:pos]) if not secret else pos)
                                 , w - 2))
        except Exception:
            pass
        _ui_add(scr, y0 + bh - 1, x0 + 2, " Enter 确认  Esc 取消 ")
        scr.refresh()
        ch = _ui_key(scr)
        if isinstance(ch, int):
            if ch in (10, 13, curses.KEY_ENTER):
                try:
                    curses.curs_set(0)
                except Exception:
                    pass
                return buf
            if ch == 27:
                try:
                    curses.curs_set(0)
                except Exception:
                    pass
                return None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0:
                    buf = buf[: pos - 1] + buf[pos:]
                    pos -= 1
            elif ch == curses.KEY_DC:
                buf = buf[:pos] + buf[pos + 1:]
            elif ch == curses.KEY_LEFT:
                pos = max(0, pos - 1)
            elif ch == curses.KEY_RIGHT:
                pos = min(len(buf), pos + 1)
            elif ch == curses.KEY_HOME:
                pos = 0
            elif ch == curses.KEY_END:
                pos = len(buf)
        elif isinstance(ch, str) and ch in ("\n", "\r"):
            try:
                curses.curs_set(0)
            except Exception:
                pass
            return buf
        elif isinstance(ch, str) and ch.isprintable():
            buf = buf[:pos] + ch + buf[pos:]
            pos += 1
        elif ch == "\x1b":
            try:
                curses.curs_set(0)
            except Exception:
                pass
            return None


def _ui_confirm(title, default=True):
    options = ["是", "否"] if default else ["否", "是"]
    idx = _ui_choice(title, options, 0)
    if idx is None:
        return None
    return options[idx] == "是"


# ---------------------------------------------------------- 兼容旧调用接口
def select_one(title, options, default=0, info=None):
    if _UI_SCREEN is None:
        return _select_one_raw(title, options, default=default, info=info)
    _flush_output()
    if not options:
        return None
    idx = _ui_choice(title, [label for label, _ in options],
                     default=default, info=info)
    return None if idx is None else options[idx][1]


def select_multi(title, options, initial=None, info=None):
    if _UI_SCREEN is None:
        return _select_multi_raw(title, options, initial=initial, info=info)
    _flush_output()
    if not options:
        return None
    return _ui_multi(title, options, initial=initial, info=info)


def read_line(prompt: str) -> str:
    if _UI_SCREEN is None:
        return _read_line_raw(prompt)
    _flush_output()
    title = prompt.strip().rstrip(":").strip() or "输入"
    value = _ui_input(title)
    return "" if value is None else value


def read_secret(prompt: str) -> str:
    if _UI_SCREEN is None:
        return _read_secret_raw(prompt)
    _flush_output()
    title = prompt.strip().rstrip(":").strip() or "密码"
    value = _ui_input(title, secret=True)
    return "" if value is None else value


def ask_text(prompt: str, default: str = "") -> str:
    if _UI_SCREEN is None:
        suffix = f" [{default}]" if default else ""
        raw = _read_line_raw(f"{prompt}{suffix}: ")
        return raw or default
    _flush_output()
    value = _ui_input(prompt, default=default)
    if value is None:
        return default
    return value or default


def pause() -> None:
    if _UI_SCREEN is None:
        return _pause_raw()
    if _OUT_BUF:
        _flush_output()
    else:
        _ui_msg("提示", "按任意键返回")


# ------------------------------------------------------------ 仪表盘
UI_GROUPS = [
    ("共享与存储", [
        ("SMB 管理", "smb_menu", "s"),
        ("iSCSI 管理", "iscsi_menu", "i"),
        ("ZFS 管理", "zfs_menu", "z"),
    ]),
    ("硬件", [
        ("硬盘管理", "disk_menu", "d"),
    ]),
    ("系统", [
        ("依赖检查 / 安装", "deps_menu", "e"),
        ("系统集成 / 一键配置", "system_menu", "c"),
        ("退出", "quit", "q"),
    ]),
]


def _ui_info() -> list:
    now = time.time()
    if _INFO_CACHE["lines"] and now - _INFO_CACHE["ts"] < 5:
        return _INFO_CACHE["lines"]
    try:
        lines = main_info_lines()
    except Exception:
        lines = ["状态读取失败"]
    _INFO_CACHE.update(ts=now, lines=lines)
    return lines


def _ui_rows() -> list:
    rows = []
    for group, items in UI_GROUPS:
        rows.append({"kind": "group", "label": group})
        for label, key, hot in items:
            rows.append({"kind": "item", "label": label, "key": key, "hot": hot})
    return rows


def _ui_first(rows) -> int:
    for i, r in enumerate(rows):
        if r["kind"] == "item":
            return i
    return 0


def _ui_move(rows, sel, step) -> int:
    for _ in range(len(rows)):
        sel = (sel + step) % len(rows)
        if rows[sel]["kind"] == "item":
            return sel
    return sel


def _ui_draw_dashboard(scr, rows, sel) -> None:
    scr.clear()
    h, w = scr.getmaxyx()
    if h < 16 or w < 52:
        _ui_add(scr, 0, 0, "终端窗口太小，请调整到至少 52x16 后重试。")
        scr.refresh()
        return
    info = _ui_info()
    max_info = max(2, h - 16)
    info = info[:max_info]
    hh = len(info) + 2
    _ui_box(scr, 0, 0, hh, w, f"nas {VERSION} · 管理面板")
    for i, line in enumerate(info):
        attr = 0
        if any(k in line for k in ("告警", "未解锁", "异常", "未设置")):
            attr = _ui_color(4)
        _ui_add(scr, 1 + i, 2, line, attr)

    y = hh + 1
    for i, row in enumerate(rows):
        if row["kind"] == "group":
            _ui_add(scr, y, 2, row["label"], curses.A_BOLD | _ui_color(1))
            y += 1
            continue
        selected = i == sel
        left = ("▸ " if selected else "  ") + row["label"]
        right = f"[{row['hot']}]"
        text = " " + _ui_pad(left, max(1, w - 8 - _ui_w(right))) + right + " "
        _ui_add(scr, y, 2, text, curses.A_REVERSE if selected else 0)
        y += 1

    _ui_add(scr, h - 1, 2,
            " ↑/↓ 选择   Enter 执行   q 退出   快捷键见方括号 ", curses.A_DIM)


def _ui_run_handler(scr, key) -> bool:
    """执行菜单项；返回 True 表示退出。"""
    if key == "quit":
        return True
    _flush_output()
    try:
        HANDLERS[key]()
    except NasError as exc:
        print(f"错误: {exc}")
    except KeyboardInterrupt:
        print("已取消")
    _INFO_CACHE["ts"] = 0.0
    _flush_output()
    return False


def _ui_dashboard(scr) -> None:
    rows = _ui_rows()
    sel = _ui_first(rows)
    while True:
        rows = _ui_rows()
        _ui_draw_dashboard(scr, rows, sel)
        scr.refresh()
        ch = _ui_key(scr)
        if isinstance(ch, int):
            if ch == curses.KEY_UP:
                sel = _ui_move(rows, sel, -1)
            elif ch == curses.KEY_DOWN:
                sel = _ui_move(rows, sel, 1)
            elif ch in (10, 13, curses.KEY_ENTER):
                if _ui_run_handler(scr, rows[sel]["key"]):
                    return
            elif ch == 27:
                return
            continue
        if ch in ("q", "\x1b"):
            return
        if ch in ("j", "k"):
            sel = _ui_move(rows, sel, 1 if ch == "j" else -1)
            continue
        if ch in ("\n", "\r"):
            if _ui_run_handler(scr, rows[sel]["key"]):
                return
            continue
        hot = {r["hot"]: r["key"] for r in rows if r["kind"] == "item"}
        if ch in hot:
            if _ui_run_handler(scr, hot[ch]):
                return


def interactive() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("nas 需要交互式终端（SSH 或本地控制台）。", file=sys.stderr)
        return 2
    if curses is None:
        return _interactive_raw()

    global _UI_SCREEN
    old_stdout = sys.stdout
    sys.stdout = _BufferedOut()
    try:
        def _main(scr):
            global _UI_SCREEN
            _UI_SCREEN = scr
            _ui_setup(scr)
            try:
                _ui_dashboard(scr)
            finally:
                _UI_SCREEN = None

        curses.wrapper(_main)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout = old_stdout
    return 0


LOGIN_SHELLS_EXCLUDE = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/sync",
    "/sbin/shutdown",
    "/sbin/halt",
}


def samba_account_names() -> set[str]:
    proc = run(["pdbedit", "-L"])
    if proc.returncode != 0:
        return set()
    return {line.split(":", 1)[0].strip() for line in proc.stdout.splitlines() if line.strip()}


def list_system_users() -> list[str]:
    """可选用户：有登录 shell 的普通用户，或任何有 Samba 账户的用户（nologin 也算）。"""
    accounts = samba_account_names()
    users = []
    for entry in pwd.getpwall():
        if entry.pw_uid == 0 or entry.pw_uid < 1000 or entry.pw_uid >= 65534:
            continue
        if entry.pw_shell in LOGIN_SHELLS_EXCLUDE and entry.pw_name not in accounts:
            continue
        users.append(entry.pw_name)
    return sorted(users)


def list_system_groups() -> list[str]:
    """只列和 Samba 用户相关的组：普通用户主组 + 有 Samba 成员的组。"""
    accounts = samba_account_names()
    primary = set()
    for name in accounts:
        try:
            primary.add(pwd.getpwnam(name).pw_gid)
        except KeyError:
            continue

    groups = []
    for entry in grp.getgrall():
        if entry.gr_gid in (0, 65534):
            continue
        if entry.gr_gid >= 1000 or entry.gr_gid in primary:
            groups.append(entry.gr_name)
        elif any(member in accounts for member in entry.gr_mem):
            groups.append(entry.gr_name)
    return sorted(groups)


def choose_visible_users(initial=None, title: str = "选择可见用户"):
    users = sorted(name for name in samba_account_names() if linux_user_exists(name))
    if not users:
        print("没有可选的用户（需要 Linux 用户且有 Samba 账户）。")
        return None
    return select_multi(title, [(name, name) for name in users], initial or [])


def choose_share(title: str = "选择共享") -> Block | None:
    conf = SmbConf(SMB_CONF).load()
    blocks = conf.shares()
    if not blocks:
        print("没有共享。")
        return None
    return select_one(title, [(f"{b.name}  ({b.params().get('path', '')})", b) for b in blocks])


def read_acl_entries(path: Path) -> list[dict]:
    proc = run(["getfacl", "-p", "-E", str(path)])
    if proc.returncode != 0:
        raise NasError((proc.stderr or proc.stdout).strip()[:300])
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        is_default = line.startswith("default:")
        if is_default:
            line = line[len("default:"):]
        parts = line.split(":")
        if len(parts) != 3:
            continue
        kind, name, perms = parts
        if kind in {"user", "group"} and name:
            entries.append({
                "type": kind,
                "name": name,
                "perms": "".join(ch for ch in "rwx" if ch in perms),
                "default": is_default,
            })
    return entries


# ---------------------------------------------------------------- ui


def ui_share_add() -> None:
    print("\n== 新建共享 ==")
    name = ask_text("共享名")
    if not name:
        print("已取消")
        return
    path = ask_text("路径", "/mnt")
    comment = ask_text("说明（可空）", "")
    read_only = ask_confirm("只读？", False)
    if read_only is None:
        return
    guest = ask_confirm("允许来宾？", False)
    if guest is None:
        return

    mode = select_one("可见性", [
        ("所有人可见", "all"),
        ("仅授权用户可见（隐藏无权限用户）", "restrict"),
        ("对所有人隐藏（只能通过路径访问）", "hidden"),
    ])
    if mode is None:
        return
    hidden = mode == "hidden"
    hide_vis = mode == "restrict"
    extra_visible: list[str] = []
    if hide_vis and ask_confirm("有没有无权限但需要显示的用户？", False):
        chosen = choose_visible_users()
        if chosen is None:
            return
        extra_visible = chosen

    create_dir = False
    if not Path(path).exists():
        answer = ask_confirm("路径不存在，自动创建目录？", True)
        if answer is None:
            return
        create_dir = answer

    flags = "只读" if read_only else "读写"
    if guest:
        flags += " 来宾"
    if hidden:
        flags += " 对所有人隐藏"
    elif hide_vis:
        flags += " 仅授权用户可见"
    if not ask_confirm(f"确认写入：{name} -> {path}（{flags}）？", True):
        print("已取消")
        return

    cmd_share_add(NS(
        name=name, path=path, comment=comment or None, read_only=read_only,
        hidden=hidden, guest=guest, create_dir=create_dir,
        hide_visibility=hide_vis, extra_visible=extra_visible,
    ))


def ui_share_edit(block: Block | None = None) -> None:
    if block is None:
        block = choose_share("选择要编辑的共享")
    if block is None:
        return

    params = block.params()
    state = {
        "name": block.name,
        "path": params.get("path", ""),
        "comment": params.get("comment", ""),
        "read_only": params.get("read only", "yes").lower() in {"yes", "true", "1", "on"},
        "browseable": params.get("browseable", "yes").lower() not in {"no", "false", "0", "off"},
        "guest": params.get("guest ok", "no").lower() in {"yes", "true", "1", "on"},
        "hide": params.get("access based share enum", "no").lower() in {"yes", "true", "1", "on"},
        "extras": load_visibility().get(block.name, []),
    }

    while True:
        if not state["browseable"]:
            vis_label = "对所有人隐藏"
        elif state["hide"]:
            vis_label = "仅授权用户可见"
            if state["extras"]:
                vis_label += "（额外显示：" + "、".join(state["extras"]) + "）"
        else:
            vis_label = "所有人可见"

        options = [
            (f"名称      {state['name']}", "name"),
            (f"路径      {state['path']}", "path"),
            (f"说明      {state['comment'] or '-'}", "comment"),
            (f"只读      {'是' if state['read_only'] else '否'}", "read_only"),
            (f"允许来宾  {'是' if state['guest'] else '否'}", "guest"),
            (f"可见性    {vis_label}", "visible"),
            ("保存并返回", "save"),
            ("取消", "cancel"),
        ]
        choice = select_one(f"编辑 {state['name']}", options)
        if choice in (None, "cancel"):
            return
        if choice == "save":
            break
        if choice == "name":
            state["name"] = ask_text("新名称", state["name"])
        elif choice == "path":
            state["path"] = ask_text("路径", state["path"])
        elif choice == "comment":
            raw = read_line(f"说明（当前 {state['comment'] or '-'}，输入 - 清除）: ")
            if raw == "-":
                state["comment"] = ""
            elif raw:
                state["comment"] = raw
        elif choice == "read_only":
            state["read_only"] = not state["read_only"]
        elif choice == "guest":
            state["guest"] = not state["guest"]
        elif choice == "visible":
            mode = select_one("可见性", [
                ("所有人可见", "all"),
                ("仅授权用户可见（隐藏无权限用户）", "restrict"),
                ("对所有人隐藏（只能通过路径访问）", "hidden"),
            ])
            if mode is None:
                return
            if mode == "hidden":
                state["browseable"] = False
                state["hide"] = False
                state["extras"] = []
            elif mode == "all":
                state["browseable"] = True
                state["hide"] = False
                state["extras"] = []
            else:
                authorized = acl_user_names(Path(state["path"])) if state["path"] else []
                print("\n有权限用户（来自文件系统 ACL）：" + ("、".join(authorized) or "无"))
                if not authorized:
                    print("共享目录还没有具名用户 ACL，请先在「设置权限」里授权。")
                    pause()
                    continue
                state["browseable"] = True
                state["hide"] = True
                has_extra = ask_confirm("有没有无权限但需要显示的用户？", bool(state["extras"]))
                if has_extra is None:
                    return
                if has_extra:
                    chosen = choose_visible_users(state["extras"] or None)
                    if chosen is None:
                        return
                    state["extras"] = chosen
                else:
                    state["extras"] = []

    create_dir = False
    if state["path"] and not Path(state["path"]).exists():
        answer = ask_confirm("路径不存在，自动创建目录？", True)
        if answer is None:
            return
        create_dir = answer


    print(f"\n名称 {state['name']}")
    print(f"路径 {state['path']}")
    print(f"说明 {state['comment'] or '-'}")
    print(f"只读 {'是' if state['read_only'] else '否'} | 来宾 {'是' if state['guest'] else '否'}")
    print(f"可见性 {vis_label}")
    if not ask_confirm("保存修改？", True):
        print("已取消")
        return

    cmd_share_edit(NS(
        name=block.name,
        new_name=state["name"] if state["name"] != block.name else None,
        path=state["path"],
        comment=state["comment"],
        create_dir=create_dir,
        read_only=state["read_only"],
        browseable=state["browseable"],
        guest=state["guest"],
        hide_visibility=state["hide"],
        extra_visible=state["extras"] if state["hide"] else [],
    ))

def ui_share_rm(block: Block | None = None) -> None:
    if block is None:
        block = choose_share("选择要删除的共享")
    if block is None:
        return
    if not ask_confirm(f"删除共享 {block.name}？（不会删除磁盘文件）", False):
        print("已取消")
        return
    cmd_share_rm(NS(name=block.name, yes=True))


def ui_acl_set(block: Block | None = None) -> None:
    if block is None:
        block = choose_share("选择要授权的共享")
    if block is None:
        return
    _, target = share_target(block.name)

    kind = select_one("选择类型", [("用户", "user"), ("组", "group")],
                      info=share_detail_lines(block))
    if kind is None:
        return

    if kind == "user":
        names = list_system_users()
        if not names:
            print("没有可选的用户（需要有 Samba 账户或登录 shell）。")
            return
        title = "选择用户"
    else:
        names = list_system_groups()
        if not names:
            print("没有可选的组。")
            return
        title = "选择组"

    entries = read_acl_entries(target)
    current: dict[str, str] = {}
    for entry in entries:
        if entry["type"] != kind or entry["default"]:
            continue
        current[entry["name"]] = current.get(entry["name"], "") + entry["perms"]

    options = []
    for name in names:
        perms = "".join(ch for ch in "rwx" if ch in current.get(name, ""))
        options.append((f"{name}  ({perms})" if perms else name, name))

    name = select_one(title, options)
    if name is None:
        return

    initial = [ch for ch in ("r", "w", "x") if ch in current.get(name, "")]
    chosen = select_multi(
        f"{name} 的权限（空格切换）",
        [("读  r", "r"), ("写  w", "w"), ("执行 x", "x")],
        initial,
    )
    if chosen is None:
        return
    if not chosen:
        print("至少选择一项权限。")
        return

    perms = "".join(ch for ch in "rwx" if ch in chosen)
    recursive = ask_confirm("递归应用到现有文件？", False)
    if recursive is None:
        return
    if not ask_confirm(f"授予 {kind}:{name} 权限 {perms}？", True):
        return

    spec = f"{name}={perms}"
    cmd_acl_set(NS(
        share=block.name,
        user=[spec] if kind == "user" else [],
        group=[spec] if kind == "group" else [],
        recursive=recursive,
    ))

def ui_acl_reset(block: Block | None = None) -> None:
    if block is None:
        block = choose_share("选择要重置权限的共享")
    if block is None:
        return

    _, target = share_target(block.name)
    entries = read_acl_entries(target)
    current: dict[tuple[str, str], str] = {}
    for entry in entries:
        if entry["default"]:
            continue
        key = (entry["type"], entry["name"])
        current[key] = current.get(key, "") + entry["perms"]

    revoke: list[str] = []
    if current:
        options = []
        for (kind, name), perms in current.items():
            readable = "".join(ch for ch in "rwx" if ch in perms)
            label = f"{'用户' if kind == 'user' else '组'} {name}  ({readable})"
            options.append((label, f"{kind}:{name}"))
        chosen = select_multi("选择要收回权限的用户/组（空格选择，可多选）", options,
                              info=share_detail_lines(block))
        if chosen is None:
            return
        revoke = chosen
        if revoke:
            print("将收回：" + "、".join(revoke))
    else:
        print("当前没有具名 ACL。")

    keep_visible: list[str] = []
    abse = block.params().get("access based share enum", "no").lower() in {"yes", "true", "1", "on"}
    revoked_users = [item.split(":", 1)[1] for item in revoke if item.startswith("user:")]
    if abse and revoked_users:
        current_extras = set(load_visibility().get(block.name, []))
        initial = [name for name in revoked_users if name in current_extras]
        keep = select_multi(
            "收回权限后仍需可见共享的用户（空格选择，可空）",
            [(name, name) for name in revoked_users],
            initial,
        )
        if keep is None:
            return
        keep_visible = keep

    recursive = ask_confirm("递归应用到现有文件？", True)
    if recursive is None:
        return
    reset_base = ask_confirm("同时重置属主为 root、目录 2770 / 文件 0770？", True)
    if reset_base is None:
        return
    if not ask_confirm("确认执行？", True):
        print("已取消")
        return

    cmd_acl_reset(NS(
        share=block.name,
        revoke=revoke,
        keep_visible=keep_visible,
        recursive=recursive,
        reset_base=reset_base,
    ))


def samba_sid_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for row in list_samba_users():
        proc = run(["pdbedit", "-Lv", row["name"]])
        for line in proc.stdout.splitlines():
            if line.startswith("User SID:"):
                mapping[line.split(":", 1)[1].strip()] = row["name"]
    return mapping


def share_detail_lines(block: Block) -> list[str]:
    params = block.params()
    path = params.get("path", "")
    lines = [f"路径 {path}"]
    if params.get("comment"):
        lines.append(f"说明 {params['comment']}")

    read_only = params.get("read only", "yes").lower() in {"yes", "true", "1", "on"}
    guest = params.get("guest ok", "no").lower() in {"yes", "true", "1", "on"}
    lines.append(f"只读 {'是' if read_only else '否'} | 来宾 {'是' if guest else '否'}")


    browseable = params.get("browseable", "yes").lower() not in {"no", "false", "0", "off"}
    abse = params.get("access based share enum", "no").lower() in {"yes", "true", "1", "on"}
    extras = load_visibility().get(block.name, [])
    if not browseable:
        visible = "对所有人隐藏"
    elif abse:
        visible = "仅授权用户可见"
        if extras:
            visible += "（额外显示：" + "、".join(extras) + "）"
    else:
        visible = "所有人可见"
    lines.append(f"可见性 {visible}")
    target = Path(path) if path else None
    if target and target.exists():
        stat = target.stat()
        try:
            owner = pwd.getpwuid(stat.st_uid).pw_name
        except KeyError:
            owner = str(stat.st_uid)
        try:
            group = grp.getgrgid(stat.st_gid).gr_name
        except KeyError:
            group = str(stat.st_gid)
        lines.append(f"属主 {owner}:{group} {format(stat.st_mode & 0o7777, '04o')}")

        named: dict[tuple[str, str], str] = {}
        for entry in read_acl_entries(target):
            if entry["default"]:
                continue
            key = (entry["type"], entry["name"])
            named[key] = "".join(ch for ch in "rwx" if ch in (named.get(key, "") + entry["perms"]))
        if named:
            lines.append("文件系统 ACL " + "  ".join(
                f"{name}={perms}" for (_, name), perms in named.items()
            ))
        else:
            lines.append("文件系统 ACL 无具名用户")
    else:
        lines.append("路径不存在")

    aces = read_share_acl(block.name)
    if aces and not (len(aces) == 1 and aces[0].startswith("S-1-1-0:")):
        mapping = samba_sid_map()
        parts = []
        for ace in aces:
            sid, rest = ace.split(":", 1)
            label = mapping.get(sid, sid[-6:])
            parts.append(f"{label}={rest.rsplit('/', 1)[-1]}")
        lines.append("共享 ACL " + "  ".join(parts))
    return lines


def ui_share_menu() -> None:
    while True:
        conf = SmbConf(SMB_CONF).load()
        blocks = conf.shares()
        options: list[tuple[str, object]] = [("＋ 新建共享", "new")]
        options += [
            (f"{b.name}  ({b.params().get('path', '')})", b)
            for b in blocks
        ]
        options.append(("返回", "back"))

        choice = select_one("共享管理", options)
        if choice in (None, "back"):
            return
        if choice == "new":
            ui_share_add()
            pause()
            continue

        block = choice
        while True:
            current = SmbConf(SMB_CONF).load().find(block.name)
            if current is None:
                break
            block = current
            action = select_one(block.name, [
                ("编辑共享", "edit"),
                ("设置权限", "grant"),
                ("重置权限", "reset"),
                ("修复已有可执行文件权限", "fixexec"),
                ("删除共享", "delete"),
                ("返回", "back"),
            ], info=share_detail_lines(block))
            if action in (None, "back"):
                break
            if action == "edit":
                ui_share_edit(block)
                pause()
                break  # 名称/路径可能已变，回到共享列表
            if action == "delete":
                ui_share_rm(block)
                pause()
                break
            if action == "grant":
                ui_acl_set(block)
            elif action == "reset":
                ui_acl_reset(block)
            elif action == "fixexec":
                if not ask_confirm(f"修复 {block.name} 中已有 .exe/.bat/.cmd 等文件的执行权限？", False):
                    pause()
                    continue
                try:
                    cmd_share_fix_exec(NS(share=block.name))
                except NasError as exc:
                    print(f"错误: {exc}")
            pause()


def ui_user_menu() -> None:
    while True:
        rows = list_samba_users()
        options: list[tuple[str, object]] = [("＋ 新建用户", "new")]
        options += [
            (f"{r['name']}  ({'禁用' if r['disabled'] else '正常'})", r)
            for r in rows
        ]
        options.append(("返回", "back"))

        choice = select_one("用户管理", options)
        if choice in (None, "back"):
            return
        if choice == "new":
            ui_user_add()
            pause()
            continue

        while True:
            rows = list_samba_users()
            row = next((r for r in rows if r["name"] == choice["name"]), None)
            if row is None:
                break
            action = select_one(row["name"], [
                ("重置密码", "password"),
                ("启用" if row["disabled"] else "禁用", "toggle"),
                ("删除用户", "delete"),
                ("返回", "back"),
            ], info=user_detail_lines(row))
            if action in (None, "back"):
                break
            if action == "password":
                ui_user_password(row["name"])
            elif action == "toggle":
                ui_user_toggle(row["name"])
            elif action == "delete":
                ui_user_delete(row["name"])
                break
            pause()


def ui_iscsi_create() -> None:
    zvols = zvol_list()
    options: list[tuple[str, object]] = [("＋ 新建 zvol", "new")]
    options += [(f"{name}  ({_size_text(size)})", (name, size)) for name, size in zvols]
    options.append(("返回", "back"))
    choice = select_one("选择 backstore", options)
    if choice in (None, "back"):
        return

    if choice == "new":
        parent = ask_text("父数据集", "cache-1/xct258/iscsi")
        name = ask_text("zvol 名称", "disk1")
        size = ask_text("大小（如 50G）", "50G")
        try:
            dataset, dev = cmd_zfs_zvol(NS(parent=parent, name=name, size=size))
        except NasError as exc:
            print(f"错误: {exc}")
            return
    else:
        dataset, size = choice
        dev = Path("/dev/zvol") / dataset
        if not dev.exists():
            print(f"设备不存在: {dev}")
            return

    backstore = ask_text("backstore 名称", dataset.rsplit("/", 1)[-1])
    default_iqn = f"iqn.{time.strftime('%Y-%m')}.lan.nas:{backstore}"
    iqn = ask_text("target IQN", default_iqn)
    initiator = ask_text("客户端 initiator IQN")
    if not initiator:
        print("已取消")
        return
    chap_user = ask_text("CHAP 用户名", "nas")
    chap_password = read_secret("CHAP 密码（回车生成随机）: ")
    if not chap_password:
        chap_password = secrets.token_urlsafe(12)

    print(f"\n设备     {dev}")
    print(f"target   {iqn}")
    print(f"客户端   {initiator}")
    print(f"CHAP     {chap_user} / {chap_password}")
    if not ask_confirm("确认创建 iSCSI 磁盘？", True):
        print("已取消")
        return

    cmd_iscsi_create(NS(
        device=str(dev), backstore=backstore, target_iqn=iqn,
        initiator=initiator, chap_user=chap_user, chap_password=chap_password,
    ))
    print("\n客户端连接信息：")
    print(f"  Target IQN : {iqn}")
    print("  Portal     : <NAS-IP>:3260")
    print(f"  CHAP 用户  : {chap_user}")
    print(f"  CHAP 密码  : {chap_password}")


def ui_iscsi_acl(target: dict) -> None:
    default_init = target["acls"][0]["node_wwn"] if target["acls"] else ""
    initiator = ask_text("客户端 initiator IQN", default_init)
    if not initiator:
        print("已取消")
        return
    chap_user = ask_text("CHAP 用户名", "nas")
    chap_password = read_secret("CHAP 密码（回车生成随机）: ")
    if not chap_password:
        chap_password = secrets.token_urlsafe(12)
    if not ask_confirm(f"授权 {initiator} 访问 {target['iqn']}？", True):
        print("已取消")
        return
    cmd_iscsi_acl(NS(
        target=target["iqn"], initiator=initiator,
        chap_user=chap_user, chap_password=chap_password,
    ))
    print(f"CHAP：{chap_user} / {chap_password}")


def ui_iscsi_acl_delete(target: dict) -> None:
    if not target["acls"]:
        print("没有已授权客户端。")
        return
    initiator = select_one(
        "选择要移除的客户端",
        [(a.get("node_wwn", "?"), a.get("node_wwn", "")) for a in target["acls"]],
    )
    if not initiator:
        return
    if not ask_confirm(f"移除客户端 {initiator}？", False):
        print("已取消")
        return
    cmd_iscsi_acl_delete(NS(target=target["iqn"], initiator=initiator))


def ui_iscsi_delete(target: dict) -> None:
    typed = read_line("输入 target IQN 确认删除: ")
    if typed != target["iqn"]:
        print("已取消")
        return
    answer = ask_confirm("同时删除 backstore 映射（zvol 不删除）？", True)
    if answer is None:
        return
    cmd_iscsi_delete(NS(target_iqn=target["iqn"], delete_backstore=answer))


def ui_iscsi_service(action: str) -> None:
    if action == "stop":
        if not ask_confirm("停止服务会断开所有 iSCSI 客户端，继续？", False):
            print("已取消")
            return
    elif action == "restart":
        if not ask_confirm("重启服务会短暂断开客户端，继续？", True):
            print("已取消")
            return
    cmd_iscsi_service(NS(action=action))


def ui_iscsi_reset() -> None:
    targets = iscsi_targets()
    stores = iscsi_storage()
    if not targets and not stores:
        print("当前没有 iSCSI 磁盘。")
        return

    print(f"将删除 {len(targets)} 个 target、{len(stores)} 个 backstore 映射。")
    print("zvol 和数据不会被删除。")
    typed = read_line('输入 RESET 确认: ')
    if typed != "RESET":
        print("已取消")
        return
    answer = ask_confirm("同时删除 backstore 映射？", True)
    if answer is None:
        return
    cmd_iscsi_reset(NS(delete_backstores=answer))


def ui_iscsi_menu() -> None:
    if not shutil.which("targetcli"):
        print("未安装 targetcli-fb：apt install targetcli-fb")
        return

    while True:
        targets = iscsi_targets()
        options: list[tuple[str, object]] = [("＋ 新建 iSCSI 磁盘", "new")]
        options += [
            (f"{t['iqn']}  ({len(t['luns'])} LUN, {len(t['acls'])} 客户端)", t)
            for t in targets
        ]
        options += [
            ("启动服务", "start"),
            ("停止服务", "stop"),
            ("重启服务", "restart"),
            ("清空所有 iSCSI 磁盘", "reset"),
            ("返回", "back"),
        ]

        state = _service_state("rtslib-fb-targetctl")
        choice = select_one(f"iSCSI 管理 · 服务 {state}", options)
        if choice in (None, "back"):
            return
        if not isinstance(choice, dict):
            if choice == "new":
                ui_iscsi_create()
            elif choice in {"start", "stop", "restart"}:
                ui_iscsi_service(choice)
            elif choice == "reset":
                ui_iscsi_reset()
            pause()
            continue

        while True:
            targets = iscsi_targets()
            target = next((t for t in targets if t["iqn"] == choice["iqn"]), None)
            if target is None:
                break
            action = select_one(target["iqn"], [
                ("添加 / 修改客户端", "acl"),
                ("删除客户端", "delacl"),
                ("删除 iSCSI 磁盘", "delete"),
                ("返回", "back"),
            ], info=iscsi_detail_lines(target))
            if action in (None, "back"):
                break
            if action == "acl":
                ui_iscsi_acl(target)
            elif action == "delacl":
                ui_iscsi_acl_delete(target)
            elif action == "delete":
                ui_iscsi_delete(target)
                break
            pause()


def ui_network_discovery_menu() -> None:
    while True:
        state = discovery_state()
        enabled = discovery_enabled()
        info = [
            f"状态 {'开' if enabled else '关'}",
            f"名称 {state['netbios'] or '未设置'}",
            f"workgroup {state['workgroup'] or '未设置'}",
            f"服务 smbd={state['smbd']} nmbd={state['nmbd']} wsdd2={state['wsdd2']}",
        ]
        if not state["wsdd_installed"]:
            info.append("wsdd2 未安装，Windows 可能不会显示")
        actions = [
            ("关闭网络发现" if enabled else "开启网络发现", "toggle"),
            ("设置网络发现名称", "name"),
            ("刷新状态", "refresh"),
            ("返回", "back"),
        ]
        choice = select_one("网络发现管理", actions, info=info)
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue
        try:
            if choice == "toggle":
                if enabled:
                    cmd_discovery_off(NS())
                else:
                    cmd_discovery_on(NS())
            elif choice == "name":
                current = state["netbios"] or "NAS"
                name = ask_text("网络发现名称", current)
                if not name:
                    print("已取消")
                    pause()
                    continue
                cmd_discovery_set_name(NS(name=name))
            print()
            cmd_discovery_status(NS())
        except NasError as exc:
            print(f"\n错误: {exc}")
        pause()


def ui_smb_menu() -> None:
    while True:
        choice = select_one("SMB 管理", [
            ("共享管理", "share"),
            ("用户管理", "user"),
            ("网络发现管理", "discovery"),
            ("返回", "back"),
        ])
        if choice in (None, "back"):
            return
        if choice == "share":
            ui_share_menu()
        elif choice == "user":
            ui_user_menu()
        elif choice == "discovery":
            ui_network_discovery_menu()


def ui_deps_menu() -> None:
    while True:
        status = dependency_status()
        info = [f"{d['name']:<18} {d['detail']}" for d in status]
        missing = [d for d in status if not d["ok"]]

        options: list[tuple[str, object]] = [
            ("一键配置本机（安装依赖 + 开机保护）", "integrate"),
        ]
        if missing:
            options.append(("安装所有缺失项", "missing"))
        for dep in missing:
            options.append((f"安装 {dep['name']}", dep["key"]))
        options.append(("刷新状态", "refresh"))
        options.append(("返回", "back"))

        choice = select_one("依赖检查 / 安装", options, info=info)
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue

        try:
            if choice == "integrate":
                run_one_click_setup()
            else:
                keys = [d["key"] for d in missing] if choice == "missing" else [choice]
                cmd_deps_install(NS(keys=keys))
        except NasError as exc:
            print(f"\n错误: {exc}")
        pause()


def ui_zfs_pools() -> None:
    while True:
        pools = zfs_pools()
        if not pools:
            print("没有存储池。")
            return
        options = [
            (f"{p['name']}  {p['health']}  {_size_text(p['alloc'])}/{_size_text(p['size'])}  {p['cap']}", p)
            for p in pools
        ]
        options.append(("返回", "back"))
        choice = select_one("存储池", options)
        if choice in (None, "back"):
            return
        pool = choice
        action = select_one(pool["name"], [
            ("启动 scrub", "scrub"),
            ("返回", "back"),
        ], info=[
            f"大小 {_size_text(pool['size'])}",
            f"已用 {_size_text(pool['alloc'])}（{pool['cap']}）",
            f"可用 {_size_text(pool['free'])}",
            f"健康 {pool['health']} · 碎片 {pool['frag']}",
        ])
        if action == "scrub":
            if ask_confirm(f"对 {pool['name']} 启动 scrub？", True):
                try:
                    cmd_zfs_scrub(NS(pool=pool["name"]))
                except NasError as exc:
                    print(f"错误: {exc}")
            pause()


def ui_zfs_datasets() -> None:
    while True:
        datasets = sorted(zfs_datasets(), key=lambda d: d["name"])
        options: list[tuple[str, object]] = [
            ("＋ 新建数据集", "new"),
            ("＋ 新建 zvol", "newzvol"),
        ]
        for d in datasets:
            depth = d["name"].count("/")
            leaf = d["name"].rsplit("/", 1)[-1]
            if d["type"] == "volume":
                label = "  " * depth + leaf + f"  [zvol {_size_text(d['used'])}]"
            else:
                label = "  " * depth + leaf
            if d.get("encryption", "off") != "off":
                label += "  [加密]"
            options.append((label, d))
        options.append(("返回", "back"))

        choice = select_one("数据集", options)
        if choice in (None, "back"):
            return

        if not isinstance(choice, dict):
            if choice == "new":
                parent = ask_text("父数据集", "cache-1")
                name = ask_text("名称", "data")
                quota = ask_text("配额（可空，如 100G）", "")
                encrypted = ask_confirm("创建加密数据集？", False)
                if encrypted is None:
                    continue
                passphrase = None
                if encrypted:
                    first = read_secret("加密密码（至少 8 位）: ")
                    second = read_secret("确认密码: ")
                    if first != second:
                        print("两次输入的密码不一致。")
                        continue
                    passphrase = first
                if not ask_confirm(f"创建数据集 {parent}/{name}？", True):
                    continue
                try:
                    cmd_zfs_create_dataset(NS(
                        parent=parent, name=name, quota=quota or None,
                        encrypted=encrypted, passphrase=passphrase))
                except NasError as exc:
                    print(f"错误: {exc}")
                pause()
            elif choice == "newzvol":
                parent = ask_text("父数据集", "cache-1/xct258/iscsi")
                name = ask_text("zvol 名称", "disk1")
                size = ask_text("大小（如 50G）", "50G")
                if not ask_confirm(f"创建 zvol {parent}/{name}（{size}，稀疏）？", True):
                    continue
                try:
                    dataset, dev = cmd_zfs_zvol(NS(parent=parent, name=name, size=size))
                    print(f"已创建 {dataset} -> {dev}")
                except NasError as exc:
                    print(f"错误: {exc}")
                pause()
            continue

        dataset = choice
        action = select_one(dataset["name"], [
            ("创建快照", "snapshot"),
            ("删除数据集", "delete"),
            ("返回", "back"),
        ], info=[
            f"类型 {dataset['type']}",
            f"已用 {_size_text(dataset['used'])} · 可用 {_size_text(dataset['avail'])}",
            f"挂载点 {dataset['mountpoint'] or '-'}",
        ])
        if action == "snapshot":
            default_name = "manual_" + time.strftime("%Y%m%d_%H%M")
            name = ask_text("快照名", default_name)
            recursive = ask_confirm("递归包含子数据集？", False)
            if recursive is None:
                continue
            if not ask_confirm(f"创建 {dataset['name']}@{name}？", True):
                continue
            try:
                cmd_zfs_snapshot_create(NS(
                    dataset=dataset["name"], name=name, recursive=recursive))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
        elif action == "delete":
            typed = read_line(f"输入数据集名 {dataset['name']} 确认删除: ")
            if typed != dataset["name"]:
                print("已取消")
                continue
            recursive = ask_confirm("递归删除子数据集？", False)
            if recursive is None:
                continue
            try:
                cmd_zfs_destroy_dataset(NS(name=dataset["name"], recursive=recursive))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()


def ui_zfs_snapshots() -> None:
    while True:
        snapshots = zfs_snapshots()
        options: list[tuple[str, object]] = [("＋ 新建快照", "new")]
        options += [
            (f"{s['name']}  ({s['created_text']}, {_size_text(s['used'])})", s)
            for s in reversed(snapshots)
        ]
        options.append(("返回", "back"))

        choice = select_one("快照", options)
        if choice in (None, "back"):
            return

        if choice == "new":
            datasets = zfs_datasets()
            if not datasets:
                print("没有数据集。")
                continue
            dataset = select_one(
                "选择数据集", [(d["name"], d["name"]) for d in datasets])
            if dataset is None:
                continue
            default_name = "manual_" + time.strftime("%Y%m%d_%H%M")
            name = ask_text("快照名", default_name)
            recursive = ask_confirm("递归包含子数据集？", False)
            if recursive is None:
                continue
            if not ask_confirm(f"创建 {dataset}@{name}？", True):
                continue
            try:
                cmd_zfs_snapshot_create(NS(dataset=dataset, name=name, recursive=recursive))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
            continue

        snapshot = choice
        action = select_one(snapshot["snapshot"], [
            ("回滚到此快照", "rollback"),
            ("删除快照", "delete"),
            ("返回", "back"),
        ], info=[
            f"数据集 {snapshot['dataset']}",
            f"创建 {snapshot['created_text']}",
            f"占用 {_size_text(snapshot['used'])}",
        ])
        if action == "rollback":
            print("回滚会丢弃该快照之后写入的数据，且不可撤销。")
            typed = read_line(f"输入完整快照名 {snapshot['name']} 确认: ")
            if typed != snapshot["name"]:
                print("已取消")
                continue
            recursive = ask_confirm("同时销毁更新的快照（-R）？", False)
            if recursive is None:
                continue
            try:
                cmd_zfs_snapshot_rollback(NS(
                    snapshot=snapshot["name"], recursive=recursive, confirm=typed))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
        elif action == "delete":
            typed = read_line(f"输入完整快照名 {snapshot['name']} 确认: ")
            if typed != snapshot["name"]:
                print("已取消")
                continue
            recursive = ask_confirm("递归删除？", False)
            if recursive is None:
                continue
            try:
                cmd_zfs_snapshot_destroy(NS(
                    snapshot=snapshot["name"], recursive=recursive))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()


def ui_zfs_encryption() -> None:
    while True:
        rows = zfs_encrypted_datasets()
        if not rows:
            print("没有加密数据集。")
            return
        options = [
            (f"{r['name']}  [{r['keystatus']}]  "
             f"{'已挂载' if r['mounted'] == 'yes' else '未挂载'}", r)
            for r in rows
        ]
        options.append(("返回", "back"))
        choice = select_one("加密数据集", options)
        if choice in (None, "back"):
            return

        row = choice
        actions: list[tuple[str, str]] = []
        if row["keystatus"] != "available":
            actions.append(("加载密钥", "load"))
        if row["keystatus"] == "available":
            actions.append(("卸载密钥", "unload"))
        if row.get("type") == "filesystem":
            if row["mounted"] == "yes":
                actions.append(("卸载挂载点", "unmount"))
            else:
                actions.append(("挂载", "mount"))
        actions.append(("返回", "back"))

        action = select_one(row["name"], actions, info=[
            f"加密算法 {row['encryption']}",
            f"密钥状态 {row['keystatus']}",
            f"keyformat {row.get('keyformat', '')} · keylocation {row.get('keylocation', '')}",
            f"挂载点 {row.get('mountpoint', '') or '-'}",
        ])
        if action in (None, "back"):
            continue

        if action == "load":
            passphrase = read_secret("密码: ")
            recursive = ask_confirm("递归加载子数据集密钥？", False)
            if recursive is None:
                continue
            try:
                cmd_zfs_load_key(NS(
                    dataset=row["name"], passphrase=passphrase, recursive=recursive))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
        elif action == "unload":
            if row["mounted"] == "yes":
                print("数据集已挂载，请先卸载挂载点。")
                pause()
                continue
            recursive = ask_confirm("递归卸载子数据集密钥？", False)
            if recursive is None:
                continue
            if not ask_confirm(f"卸载 {row['name']} 的密钥？", False):
                continue
            try:
                cmd_zfs_unload_key(NS(
                    dataset=row["name"], recursive=recursive, force=False))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
        elif action == "unmount":
            if not ask_confirm(f"卸载挂载点 {row.get('mountpoint', '')}？", False):
                continue
            try:
                cmd_zfs_unmount(NS(dataset=row["name"]))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()
        elif action == "mount":
            try:
                cmd_zfs_mount(NS(dataset=row["name"]))
            except NasError as exc:
                print(f"错误: {exc}")
            pause()


def ui_zfs_menu() -> None:
    if not zfs_available():
        print("未安装 ZFS：apt install zfsutils-linux")
        return
    while True:
        choice = select_one("ZFS 管理", [
            ("存储池", "pools"),
            ("数据集", "datasets"),
            ("快照", "snapshots"),
            ("自动快照", "auto_snapshot"),
            ("密钥管理", "encryption"),
            ("返回", "back"),
        ])
        if choice in (None, "back"):
            return
        if choice == "pools":
            ui_zfs_pools()
        elif choice == "datasets":
            ui_zfs_datasets()
        elif choice == "snapshots":
            ui_zfs_snapshots()
        elif choice == "auto_snapshot":
            ui_auto_snapshot_menu()
        elif choice == "encryption":
            ui_zfs_encryption()


def _disk_label(disk: dict, pool_map: dict[str, str]) -> str:
    pool = pool_map.get(disk["path"], "") or "未使用"
    kind = "HDD" if disk["rota"] else "SSD"
    model = (disk["model"] or "未知")[:26]
    return (
        f"{disk['name']:<7} [{pool}] {_size_text(disk['size']):>7}  "
        f"{kind:<3} {disk['tran'] or '-':<5} {model}"
    )


def ui_disk_detail(disk: dict) -> None:
    while True:
        actions: list[tuple[str, str]] = [("刷新", "refresh")]
        if shutil.which("smartctl"):
            actions += [
                ("SMART 短自检", "short"),
                ("SMART 长自检", "long"),
                ("查看自检结果", "selftest"),
            ]
        actions.append(("返回", "back"))
        action = select_one(disk["name"], actions, info=disk_detail_lines(disk))
        if action in (None, "back"):
            return
        if action == "refresh":
            continue
        if not shutil.which("smartctl"):
            print("未安装 smartctl：apt install smartmontools")
            pause()
            continue
        if action in {"short", "long"}:
            label = "短" if action == "short" else "长"
            if not ask_confirm(f"对 {disk['path']} 启动 SMART {label}自检？", True):
                continue
            proc = run(["smartctl", "-t", action, disk["path"]],
                       check=False, timeout=30)
            print((proc.stdout or proc.stderr).strip())
            pause()
        elif action == "selftest":
            proc = run(["smartctl", "-l", "selftest", disk["path"]],
                       check=False, timeout=30)
            print((proc.stdout or proc.stderr).strip())
            pause()


def ui_disk_list() -> None:
    while True:
        rows = disk_list()
        if not rows:
            print("没有检测到硬盘。")
            return
        pool_map = disk_pool_map()
        options = [(_disk_label(disk, pool_map), disk["path"]) for disk in rows]
        options += [("刷新", "refresh"), ("返回", "back")]
        choice = select_one("硬盘列表", options)
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue
        disk = next((row for row in rows if row["path"] == choice), None)
        if disk is not None:
            ui_disk_detail(disk)


def ui_disk_create_pool() -> None:
    if not zfs_available():
        print("未安装 ZFS：apt install zfsutils-linux zfs-dkms")
        return
    rows = disk_list()
    pool_map = disk_pool_map()
    free = [
        disk for disk in rows
        if disk["path"] not in pool_map and disk_is_free(disk, pool_map)
    ]
    if not free:
        print("没有可用于新建存储池的空闲硬盘。")
        print("硬盘需要没有分区、文件系统或 ZFS 池成员。")
        return

    options = [(_disk_label(disk, pool_map), disk["path"]) for disk in free]
    selected = select_multi("选择硬盘（空格勾选）", options)
    if not selected:
        return
    by_path = {disk["path"]: disk for disk in free}
    disks = [by_path[path] for path in selected]

    layout = select_one("RAID 布局", [
        ("单盘 stripe（无冗余）", "stripe"),
        ("镜像 mirror（至少 2 块）", "mirror"),
        ("RAIDZ1（至少 3 块）", "raidz1"),
        ("RAIDZ2（至少 4 块）", "raidz2"),
        ("RAIDZ3（至少 5 块）", "raidz3"),
        ("返回", "back"),
    ])
    if layout in (None, "back"):
        return

    minimum = {"stripe": 1, "mirror": 2, "raidz1": 3, "raidz2": 4, "raidz3": 5}
    if len(disks) < minimum[layout]:
        print(f"{layout} 至少需要 {minimum[layout]} 块硬盘。")
        return
    if layout == "stripe" and len(disks) > 1:
        if not ask_confirm("stripe 多盘没有冗余，继续？", False):
            return

    pool = ask_text("存储池名称")
    if not POOL_NAME_RE.fullmatch(pool):
        print("池名称不合法：只能字母开头，包含字母、数字、下划线、点、冒号和短横线。")
        return
    if pool in {row["name"] for row in zfs_pools()}:
        print(f"存储池已存在: {pool}")
        return

    print("\n将创建存储池")
    print(f"  名称   {pool}")
    print(f"  布局   {layout}")
    for disk in disks:
        print(f"  磁盘   {disk['path']}  {_size_text(disk['size'])}  {disk['model']}")
    print("\n警告：会清除这些磁盘上的分区和文件系统。")
    typed = read_line(f"输入池名 {pool} 确认: ")
    if typed != pool:
        print("已取消")
        return

    args = [
        "zpool", "create", "-f", "-m", f"/mnt/{pool}",
        "-o", "ashift=12",
        "-O", "acltype=posixacl",
        "-O", "compression=lz4",
        "-O", "xattr=sa",
        pool,
    ]
    if layout != "stripe":
        args.append(layout)
    args.extend(disk["path"] for disk in disks)

    try:
        run(args, check=True, timeout=600)
    except NasError as exc:
        print(f"创建失败: {exc}")
        return
    run(["zpool", "set", "cachefile=/etc/zfs/zpool.cache", pool], check=False)
    print(f"已创建存储池 {pool}，挂载点 /mnt/{pool}")
    status = run(["zpool", "status", pool], check=False)
    print(status.stdout.rstrip())


def ui_disk_import_pool() -> None:
    if not zfs_available():
        print("未安装 ZFS：apt install zfsutils-linux zfs-dkms")
        return
    pools = zpool_importable()
    if not pools:
        print("没有可导入的存储池。")
        return
    choice = select_one(
        "可导入的存储池",
        [(f"{row['name']}  [{row['state'] or '未知'}]", row["name"]) for row in pools]
        + [("返回", "back")],
    )
    if choice in (None, "back"):
        return
    if not ask_confirm(f"导入存储池 {choice}？", True):
        return
    try:
        run(["zpool", "import", choice], check=True, timeout=300)
    except NasError as exc:
        print(f"导入失败: {exc}")
        if not ask_confirm("尝试强制导入 (-f)？可能来自其他系统或主机 ID 不同。", False):
            return
        try:
            run(["zpool", "import", "-f", choice], check=True, timeout=300)
        except NasError as force_exc:
            print(f"强制导入失败: {force_exc}")
            return
    run(["zpool", "set", "cachefile=/etc/zfs/zpool.cache", choice], check=False)
    print(f"已导入存储池 {choice}")
    status = run(["zpool", "status", choice], check=False)
    print(status.stdout.rstrip())
    apply_share_locks()
    if shutil.which("targetcli"):
        apply_iscsi_locks()


def ui_space_monitor_menu() -> None:
    if not zfs_available():
        print("未安装 ZFS。")
        return
    while True:
        config = load_space_config()
        targets = space_targets()
        alerts = load_space_alerts()
        push = load_push_config()
        info = [
            f"监控 {'开启' if config['enabled'] else '关闭'}",
            f"推送 {'开启' if push['enabled'] else '关闭'}",
            f"当前告警 {len(alerts)} 处",
        ]
        if not config["enabled"]:
            info.append("开启后按系统盘和各池阈值检查剩余空间")
        options: list[tuple[str, object]] = [
            ("关闭空间监控" if config["enabled"] else "开启空间监控", "toggle"),
        ]
        for target in targets:
            key = target["name"]
            label = "系统盘 /" if target["kind"] == "system" else key
            threshold = space_threshold(config, key)
            state = "不足" if threshold and target["percent"] < threshold else "正常"
            if threshold <= 0:
                state = "已关闭"
            options.append((
                f"{label}  剩余 {space_usage_text(target)}  "
                f"阈值 {threshold}%  {state}",
                key,
            ))
        options += [
            ("推送提醒设置", "push"),
            ("刷新", "refresh"),
            ("返回", "back"),
        ]
        choice = select_one("硬盘空间监控", options, info=info)
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue
        if choice == "toggle":
            config["enabled"] = not config["enabled"]
            save_space_config(config)
            sync_hdd_monitor_service()
            if config["enabled"]:
                check_space_alerts()
                print("已开启空间监控。")
            else:
                save_space_alerts({})
                print("已关闭空间监控。")
            pause()
            continue
        if choice == "push":
            ui_hdd_push_settings()
            continue
        key = str(choice)
        label = "系统盘 /" if key == SYSTEM_SPACE_KEY else key
        current = space_threshold(config, key)
        raw = ask_text(f"{label} 剩余空间阈值（%，0 关闭）", str(current))
        if not raw.isdigit() or not 0 <= int(raw) <= 99:
            print("阈值必须是 0-99 的整数。")
            pause()
            continue
        if key == SYSTEM_SPACE_KEY:
            config["system_threshold"] = int(raw)
        else:
            config["thresholds"][key] = int(raw)
        save_space_config(config)
        sync_hdd_monitor_service()
        check_space_alerts()
        print(f"已设置 {label} 阈值为 {int(raw)}%"
              + ("（关闭提醒）" if int(raw) == 0 else ""))
        pause()


def ui_disk_menu() -> None:
    while True:
        rows = disk_list()
        pool_map = disk_pool_map()
        free = sum(1 for disk in rows if disk_is_free(disk, pool_map))
        choice = select_one("硬盘管理", [
            ("磁盘列表 / SMART", "list"),
            ("机械硬盘休眠", "sleep"),
            ("空间监控", "space"),
            ("创建 ZFS 池", "create"),
            ("导入 ZFS 池", "import"),
            ("返回", "back"),
        ], info=[
            f"检测到 {len(rows)} 块硬盘 · {free} 块未使用",
        ])
        if choice in (None, "back"):
            return
        if choice == "list":
            ui_disk_list()
        elif choice == "sleep":
            ui_hdd_sleep_menu()
            pause()
        elif choice == "space":
            ui_space_monitor_menu()
            pause()
        elif choice == "create":
            ui_disk_create_pool()
            pause()
        elif choice == "import":
            ui_disk_import_pool()
            pause()


def _hdd_sleep_label(disk: dict, settings: dict[str, dict],
                     pool_map: dict[str, str], status: dict[str, dict],
                     alerts: dict[str, dict]) -> str:
    key = hdd_sleep_key(disk)
    value = settings.get(key, {})
    minutes = value.get("minutes")
    timeout = f"{minutes} 分钟" if minutes else "关闭"
    cached = status.get(key, {})
    state = cached.get("state") or hdd_power_state(disk["path"])
    changed = cached.get("since")
    change_text = ""
    if changed:
        try:
            change_text = " 上次 " + time.strftime(
                "%m-%d %H:%M", time.localtime(float(changed)))
        except (TypeError, ValueError, OSError):
            pass
    pool = pool_map.get(disk["path"], "") or "未使用"
    alert_text = "  [异常唤醒-已取消]" if key in alerts else ""
    return (
        f"{disk['name']:<7} [{pool}] {_size_text(disk['size']):>7}  "
        f"休眠 {timeout:<7} 当前 {state}{change_text}{alert_text}"
    )


def hdd_history_lines(disk: dict) -> list[str]:
    key = hdd_sleep_key(disk)
    history = (load_hdd_status().get(key, {}) or {}).get("history") or []
    lines = [f"最近 {len(history[-50:])} 条记录（最多 50 条）", ""]
    if not history:
        lines.append("暂无唤醒/休眠记录。")
        return lines
    lines.append(f"{'时间':<20}  事件")
    for event in reversed(history[-50:]):
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(float(event.get("time", 0))))
        except (TypeError, ValueError, OSError):
            stamp = "未知时间"
        name = "唤醒" if event.get("event") == "wake" else "休眠"
        lines.append(f"{stamp:<20}  {name}")
    return lines


def ui_hdd_sleep_detail(disk: dict) -> None:
    while True:
        settings = load_hdd_sleep()
        alerts = load_hdd_alerts()
        key = hdd_sleep_key(disk)
        value = settings.get(key, {})
        minutes = value.get("minutes")
        alert = alerts.get(key)
        cached = load_hdd_status().get(key) or {}
        changed = cached.get("since")
        if changed:
            try:
                changed_text = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(float(changed)))
            except (TypeError, ValueError, OSError):
                changed_text = "未知"
        else:
            changed_text = "未知"
        info = [
            f"设备 {disk['path']}",
            f"型号 {disk['model'] or '未知'}",
            f"当前状态 {cached.get('state') or hdd_power_state(disk['path'])}",
            f"空闲休眠 {'关闭' if not minutes else str(minutes) + ' 分钟'}",
            f"上次状态变化 {changed_text}",
        ]
        if alert:
            try:
                alert_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(float(alert.get("time", 0))))
            except (TypeError, ValueError, OSError):
                alert_time = "未知时间"
            info.append(
                f"异常唤醒已取消休眠: {alert.get('reason', '')}（{alert_time}）"
            )
        actions = [
            ("设置空闲休眠时间", "set"),
            ("立即休眠", "sleep"),
            ("取消休眠设置", "off"),
            ("查看唤醒/休眠记录", "history"),
        ]
        if alert:
            actions.append(("清除异常提示", "clear_alert"))
        actions += [("刷新", "refresh"), ("返回", "back")]
        action = select_one(disk["name"], actions, info=info)
        if action in (None, "back", "refresh"):
            if action == "refresh":
                continue
            return
        if action == "set":
            choice = select_one("空闲多久后休眠", [
                ("5 分钟", 5), ("10 分钟", 10), ("15 分钟", 15),
                ("20 分钟", 20), ("30 分钟", 30), ("60 分钟", 60),
                ("120 分钟", 120), ("180 分钟", 180), ("返回", "back"),
            ])
            if choice in (None, "back"):
                continue
            if not ask_confirm(f"设置 {disk['path']} 空闲 {choice} 分钟后休眠？", True):
                continue
            proc = run(["hdparm", "-S", hdd_sleep_value(choice), disk["path"]],
                       check=False, timeout=20)
            if proc.returncode != 0:
                print((proc.stderr or proc.stdout).strip()[:400])
            else:
                print((proc.stdout or proc.stderr).strip())
                alerts.pop(key, None)
                save_hdd_alerts(alerts)
                settings[key] = {
                    "minutes": choice,
                    "name": disk["name"],
                    "model": disk["model"],
                    "armed_at": time.time(),
                }
                save_hdd_sleep(settings)
                sync_hdd_monitor_service()
                print(f"已设置 {disk['path']}：空闲 {choice} 分钟后休眠")
            pause()
        elif action == "sleep":
            if not ask_confirm(f"立即让 {disk['path']} 休眠？", False):
                continue
            proc = run(["hdparm", "-y", disk["path"]], check=False, timeout=20)
            print((proc.stdout or proc.stderr).strip()[:400])
            pause()
        elif action == "off":
            proc = run(["hdparm", "-S", "0", disk["path"]], check=False, timeout=20)
            if proc.returncode != 0:
                print((proc.stderr or proc.stdout).strip()[:400])
            else:
                settings.pop(key, None)
                save_hdd_sleep(settings)
                alerts.pop(key, None)
                save_hdd_alerts(alerts)
                sync_hdd_monitor_service()
                print(f"已取消 {disk['path']} 的休眠设置")
            pause()
        elif action == "history":
            print("\n".join(hdd_history_lines(disk)))
            pause()
        elif action == "clear_alert":
            alerts.pop(key, None)
            save_hdd_alerts(alerts)
            print("已清除异常提示；该盘当前保持常转。")
            pause()


PUSH_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PUSH_TOPIC_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,128}$")


def ui_hdd_push_settings() -> None:
    while True:
        config = load_push_config()
        info = [
            f"状态 {'已开启' if config['enabled'] else '已关闭'}"
            f" · MQTT {'推送' if config['push_to_mqtt'] else '仅记录'}",
            f"地址 {config['url']}",
            f"来源 {config['server_name']}",
            f"主题 {config['topic']}",
            "事件 每次进入休眠 / 被唤醒（仅限已设置休眠的机械盘）",
        ]
        actions = [
            ("关闭推送提醒" if config["enabled"] else "开启推送提醒", "toggle"),
            ("设置推送地址", "url"),
            ("设置来源名称 server_name", "server"),
            ("设置主题 topic", "topic"),
            ("切换 MQTT 推送", "mqtt"),
            ("发送测试推送", "test"),
            ("返回", "back"),
        ]
        action = select_one("推送提醒设置", actions, info=info)
        if action in (None, "back"):
            return
        if action == "toggle":
            config["enabled"] = not config["enabled"]
            save_push_config(config)
            if config["enabled"]:
                print("已开启推送提醒：硬盘休眠/唤醒时会发送通知。")
                if not HDD_MONITOR_UNIT.exists():
                    print("提示: 状态监控服务未安装，"
                          "请先在「系统集成 / 一键配置」中安装。")
            else:
                print("已关闭推送提醒。")
            pause()
        elif action == "url":
            url = ask_text("推送地址", config["url"]).strip()
            if not url.startswith(("http://", "https://")):
                print("地址必须以 http:// 或 https:// 开头，未修改。")
            else:
                config["url"] = url
                save_push_config(config)
                print("已保存推送地址。")
            pause()
        elif action == "server":
            name = ask_text("来源名称 server_name",
                            config["server_name"]).strip()
            if not PUSH_NAME_RE.match(name):
                print("来源名称只能包含字母、数字、点、下划线、短横线（1-64 位）。")
            else:
                config["server_name"] = name
                save_push_config(config)
                print("已保存来源名称。")
            pause()
        elif action == "topic":
            topic = ask_text("主题 topic", config["topic"]).strip()
            if not PUSH_TOPIC_RE.match(topic):
                print("主题只能包含字母、数字、点、下划线、短横线和斜杠（1-128 位）。")
            else:
                config["topic"] = topic
                save_push_config(config)
                print("已保存主题。")
            pause()
        elif action == "mqtt":
            config["push_to_mqtt"] = not config["push_to_mqtt"]
            save_push_config(config)
            print("已切换为 "
                  + ("推送到 MQTT。" if config["push_to_mqtt"] else "仅保存记录，不推送 MQTT。"))
            pause()
        elif action == "test":
            message = "\n".join([
                "- 这是一条来自 nas 的测试通知。",
                f"- 来源：{config['server_name']}",
                f"- 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            ])
            if push_message("NAS 推送测试", message, "info", config=config):
                print("测试推送已发送。")
            pause()


def ui_hdd_sleep_menu() -> None:
    if not shutil.which("hdparm"):
        print("未安装 hdparm：apt install hdparm")
        return
    while True:
        rows = [disk for disk in disk_list() if disk["rota"]]
        if not rows:
            print("没有检测到机械硬盘。")
            return
        settings = load_hdd_sleep()
        status = load_hdd_status()
        alerts = load_hdd_alerts()
        push_config = load_push_config()
        pool_map = disk_pool_map()
        options = [
            (_hdd_sleep_label(disk, settings, pool_map, status, alerts), disk["path"])
            for disk in rows
        ]
        options += [("推送提醒设置", "push"), ("刷新", "refresh"), ("返回", "back")]
        monitor = _unit_state("nas-hdd-monitor.service", "is-active") \
            if HDD_MONITOR_UNIT.exists() else "未安装"
        info = [
            f"休眠服务 {'已安装' if HDD_SLEEP_UNIT.exists() else '未安装（请运行系统集成）'}",
            f"状态监控 {monitor}",
            f"异常保护 {len(alerts)} 块盘",
            f"推送提醒 {'已开启' if push_config['enabled'] else '已关闭'}",
        ]
        choice = select_one("机械硬盘休眠", options, info=info)
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue
        if choice == "push":
            ui_hdd_push_settings()
            continue
        disk = next((row for row in rows if row["path"] == choice), None)
        if disk is not None:
            ui_hdd_sleep_detail(disk)


# ---------------------------------------------------------------- integration

GUARD_UNIT_TEXT = """[Unit]
Description=NAS locked dataset guard (iSCSI / mountpoints)
After=zfs-import.target zfs-mount.service
Before=smbd.service nmbd.service wsdd2.service rtslib-fb-targetctl.service
ConditionPathExists=/usr/local/bin/nas

[Service]
Type=oneshot
Environment=NAS_BOOT_GUARD=1
ExecStart=/usr/local/bin/nas
RemainAfterExit=yes
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
"""

HDD_MONITOR_UNIT_TEXT = """[Unit]
Description=NAS HDD sleep and ZFS space monitor
After=zfs-import.target zfs-mount.service nas-hdd-sleep.service
ConditionPathExists=/usr/local/bin/nas

[Service]
Type=simple
Environment=NAS_HDD_MONITOR=1
Environment=NAS_HDD_MONITOR_INTERVAL=60
ExecStart=/usr/local/bin/nas
Restart=on-failure
RestartSec=10
Nice=10
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
"""

HDD_SLEEP_UNIT_TEXT = """[Unit]
Description=NAS HDD spindown settings
After=zfs-import.target zfs-mount.service
Before=smbd.service nmbd.service wsdd2.service rtslib-fb-targetctl.service
ConditionPathExists=/usr/local/bin/nas

[Service]
Type=oneshot
Environment=NAS_HDD_SLEEP=1
ExecStart=/usr/local/bin/nas
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
"""


def unit_exists(name: str) -> bool:
    return run(["systemctl", "cat", name], check=False).returncode == 0


def _unit_state(name: str, state: str) -> str:
    proc = run(["systemctl", state, name], check=False)
    return (proc.stdout or proc.stderr).strip() or "unknown"


def install_guard_unit() -> None:
    need_root()
    changed = True
    try:
        old = GUARD_UNIT.read_text(encoding="utf-8")
        changed = old != GUARD_UNIT_TEXT
    except OSError:
        pass
    if changed:
        GUARD_UNIT.parent.mkdir(parents=True, exist_ok=True)
        tmp = GUARD_UNIT.with_name(GUARD_UNIT.name + ".tmp")
        tmp.write_text(GUARD_UNIT_TEXT, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, GUARD_UNIT)
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", "nas-lock-guard.service"], check=True)
    run(["systemctl", "restart", "nas-lock-guard.service"], check=True)


def install_hdd_sleep_unit() -> None:
    need_root()
    changed = True
    try:
        old = HDD_SLEEP_UNIT.read_text(encoding="utf-8")
        changed = old != HDD_SLEEP_UNIT_TEXT
    except OSError:
        pass
    if changed:
        HDD_SLEEP_UNIT.parent.mkdir(parents=True, exist_ok=True)
        tmp = HDD_SLEEP_UNIT.with_name(HDD_SLEEP_UNIT.name + ".tmp")
        tmp.write_text(HDD_SLEEP_UNIT_TEXT, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, HDD_SLEEP_UNIT)
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", "nas-hdd-sleep.service"], check=True)
    run(["systemctl", "restart", "nas-hdd-sleep.service"], check=True)


def sync_hdd_monitor_service() -> None:
    if not HDD_MONITOR_UNIT.exists():
        return
    if load_hdd_sleep() or space_monitor_needed():
        run(["systemctl", "enable", "nas-hdd-monitor.service"], check=False)
        run(["systemctl", "restart", "nas-hdd-monitor.service"], check=False)
    else:
        run(["systemctl", "disable", "--now", "nas-hdd-monitor.service"], check=False)


def install_hdd_monitor_unit() -> None:
    need_root()
    changed = True
    try:
        old = HDD_MONITOR_UNIT.read_text(encoding="utf-8")
        changed = old != HDD_MONITOR_UNIT_TEXT
    except OSError:
        pass
    if changed:
        HDD_MONITOR_UNIT.parent.mkdir(parents=True, exist_ok=True)
        tmp = HDD_MONITOR_UNIT.with_name(HDD_MONITOR_UNIT.name + ".tmp")
        tmp.write_text(HDD_MONITOR_UNIT_TEXT, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, HDD_MONITOR_UNIT)
    run(["systemctl", "daemon-reload"], check=True)
    sync_hdd_monitor_service()


def guard_actions(*, reload: bool) -> tuple[int, list[str], list[str]]:
    locked_count = 0
    if zfs_available():
        try:
            rows = zfs_encrypted_datasets()
        except NasError:
            rows = []
        for row in rows:
            if row.get("type") == "filesystem" and row.get("mounted") != "yes":
                lock_mountpoint(row)
                locked_count += 1
    apply_share_locks(reload=reload)
    hidden_targets: list[str] = []
    hidden_stores: list[str] = []
    if shutil.which("targetcli"):
        hidden_targets, hidden_stores = apply_iscsi_locks()
    return locked_count, hidden_targets, hidden_stores


def boot_guard() -> int:
    if os.geteuid() != 0:
        print("nas-guard: 需要 root", file=sys.stderr)
        return 0
    try:
        locked, targets, stores = guard_actions(reload=False)
        print(
            f"nas-guard: 锁定挂载点 {locked}，隐藏 target {len(targets)}，"
            f"隐藏 backstore {len(stores)}"
        )
    except Exception as exc:
        print(f"nas-guard 失败: {exc}", file=sys.stderr)
    return 0


def system_status_lines() -> list[str]:
    lines = []
    installed = GUARD_UNIT.exists()
    enabled = _unit_state("nas-lock-guard.service", "is-enabled") if installed else "未安装"
    active = _unit_state("nas-lock-guard.service", "is-active") if installed else "-"
    lines.append(f"开机保护  {'已安装' if installed else '未安装'} · {enabled} · {active}")
    if HDD_SLEEP_UNIT.exists():
        lines.append(
            "硬盘休眠  "
            f"{_unit_state('nas-hdd-sleep.service', 'is-enabled')} · "
            f"{_unit_state('nas-hdd-sleep.service', 'is-active')}"
        )
    if HDD_MONITOR_UNIT.exists():
        lines.append(
            "硬盘监控  "
            f"{_unit_state('nas-hdd-monitor.service', 'is-enabled')} · "
            f"{_unit_state('nas-hdd-monitor.service', 'is-active')}"
        )

    if AUTO_SNAP_TIMER.exists():
        lines.append(
            "自动快照  "
            f"{_unit_state('nas-auto-snapshot.timer', 'is-enabled')} · "
            f"{_unit_state('nas-auto-snapshot.timer', 'is-active')}"
        )

    if unit_exists("zfs-load-key.service"):
        lines.append(f"自动解锁  {_unit_state('zfs-load-key.service', 'is-enabled')}（应为 masked）")

    if zfs_available():
        try:
            rows = [row for row in zfs_encrypted_datasets()
                    if row.get("type") == "filesystem"]
        except NasError:
            rows = []
        if rows:
            locked = sum(1 for row in rows if row.get("keystatus") != "available")
            noauto = sum(1 for row in rows if row.get("canmount") == "noauto")
            lines.append(f"加密数据集  {len(rows)} 个 · 未解锁 {locked} · noauto {noauto}")

    target_names, store_names = iscsi_suspended_summary() if shutil.which("targetcli") else ([], [])
    lines.append(f"隐藏 target  {len(target_names)} 个")
    if space_monitor_needed() or load_space_alerts():
        space_alerts = load_space_alerts()
        lines.append(
            f"空间监控  {'开启' if space_monitor_needed() else '关闭'}"
            f" · 告警 {len(space_alerts)} 处"
        )
    return lines


def cmd_system_integrate(args) -> None:
    need_root()
    missing = [d for d in dependency_status() if not d["ok"] and not d.get("optional")]
    if missing:
        raise NasError("还有依赖未安装: " + "、".join(d["name"] for d in missing))

    noauto = 0
    if zfs_available():
        for row in zfs_encrypted_datasets():
            if row.get("type") != "filesystem" or "/" not in row["name"]:
                continue
            if row.get("mountpoint") == "/":
                continue
            if row.get("canmount") != "noauto":
                run(["zfs", "set", "canmount=noauto", row["name"]], check=True)
                noauto += 1

    install_guard_unit()
    install_hdd_sleep_unit()
    install_hdd_monitor_unit()

    services = [
        "smbd", "nmbd", "wsdd2", "rtslib-fb-targetctl",
        "zfs-import-cache", "zfs-mount", "zfs-zed",
    ]
    enabled = []
    for service in services:
        if unit_exists(service):
            run(["systemctl", "enable", "--now", service], check=False)
            enabled.append(service)

    if shutil.which("targetcli") and ISCSI_CONFIG.exists():
        iscsi_desired_config()

    apply_share_locks()
    if shutil.which("targetcli"):
        hidden_targets, hidden_stores = apply_iscsi_locks()
        if hidden_targets:
            print("已隐藏 iSCSI target: " + "、".join(hidden_targets))
        if hidden_stores:
            print("已隐藏 iSCSI backstore: " + "、".join(hidden_stores))

    print("系统集成完成")
    print(f"  canmount=noauto 新设置 {noauto} 个数据集")
    print(f"  开机保护服务 {'、'.join(enabled) if enabled else '无'}")
    print(f"  开机保护单元 {GUARD_UNIT}")
    print(f"  硬盘休眠单元 {HDD_SLEEP_UNIT}")
    print(f"  硬盘监控单元 {HDD_MONITOR_UNIT}")


def run_one_click_setup() -> None:
    status = dependency_status()
    missing = [d for d in status if not d["ok"]]
    if missing:
        print("缺失依赖: " + "、".join(d["name"] for d in missing))
        if not ask_confirm("先安装这些依赖？", True):
            print("已取消")
            return
        cmd_deps_install(NS(keys=[d["key"] for d in missing]))
    cmd_system_integrate(NS())


def ui_system_menu() -> None:
    while True:
        choice = select_one("系统集成 / 一键配置", [
            ("一键配置本机（含缺失依赖）", "setup"),
            ("重新应用锁定状态", "apply"),
            ("刷新状态", "refresh"),
            ("返回", "back"),
        ], info=system_status_lines())
        if choice in (None, "back"):
            return
        if choice == "refresh":
            continue
        try:
            if choice == "setup":
                run_one_click_setup()
            else:
                locked, targets, stores = guard_actions(reload=True)
                print(f"锁定挂载点 {locked}，隐藏 target {len(targets)}，"
                      f"隐藏 backstore {len(stores)}")
        except NasError as exc:
            print(f"错误: {exc}")
        pause()


# ---------------------------------------------------------------- main


MENU = [
    ("SMB 管理", "smb_menu"),
    ("iSCSI 管理", "iscsi_menu"),
    ("ZFS 管理", "zfs_menu"),
    ("硬盘管理", "disk_menu"),
    ("依赖检查 / 安装", "deps_menu"),
    ("系统集成 / 一键配置", "system_menu"),
]

HANDLERS = {
    "smb_menu": ui_smb_menu,
    "iscsi_menu": ui_iscsi_menu,
    "zfs_menu": ui_zfs_menu,
    "disk_menu": ui_disk_menu,
    "deps_menu": ui_deps_menu,
    "system_menu": ui_system_menu,
}


def user_detail_lines(row: dict) -> list[str]:
    lines = []
    if row["linux"]:
        entry = pwd.getpwnam(row["name"])
        lines.append(f"Linux 账户：uid {entry.pw_uid}，shell {entry.pw_shell}")
    else:
        lines.append("Linux 账户：不存在")
    lines.append(f"Samba 状态：{'禁用' if row['disabled'] else '正常'}")
    proc = run(["pdbedit", "-Lv", row["name"]])
    for line in proc.stdout.splitlines():
        if line.startswith("User SID:"):
            lines.append("SID " + line.split(":", 1)[1].strip())
    return lines


def ui_user_add() -> None:
    name = ask_text("用户名")
    if not name:
        print("已取消")
        return
    password = read_secret("密码: ")
    confirm = read_secret("确认密码: ")
    if password != confirm:
        print("两次输入的密码不一致。")
        return
    if any(row["name"] == name for row in list_samba_users()):
        print(f"Samba 用户已存在: {name}")
        return
    create_linux = False
    if not linux_user_exists(name):
        answer = ask_confirm("Linux 用户不存在，是否创建（nologin）？", True)
        if answer is None:
            return
        create_linux = answer
    if not ask_confirm(f"创建用户 {name}？", True):
        print("已取消")
        return
    cmd_user_add(NS(name=name, password=password, create_linux=create_linux))


def ui_user_password(name: str | None = None) -> None:
    if name is None:
        rows = list_samba_users()
        if not rows:
            print("没有 Samba 用户。")
            return
        name = select_one("选择用户", [(r["name"], r["name"]) for r in rows])
        if name is None:
            return
    password = read_secret("新密码: ")
    confirm = read_secret("确认密码: ")
    if password != confirm:
        print("两次输入的密码不一致。")
        return
    if not ask_confirm(f"重置 {name} 的密码？", True):
        print("已取消")
        return
    cmd_user_password(NS(name=name, password=password))


def ui_user_toggle(name: str | None = None) -> None:
    if name is None:
        rows = list_samba_users()
        if not rows:
            print("没有 Samba 用户。")
            return
        name = select_one("选择用户", [(r["name"], r["name"]) for r in rows])
        if name is None:
            return
    cmd_user_toggle(NS(name=name))


def ui_user_delete(name: str | None = None) -> None:
    if name is None:
        rows = list_samba_users()
        if not rows:
            print("没有 Samba 用户。")
            return
        name = select_one("选择用户", [(r["name"], r["name"]) for r in rows])
        if name is None:
            return
    delete_linux = False
    if linux_user_exists(name):
        answer = ask_confirm("同时删除 Linux 系统用户？", False)
        if answer is None:
            return
        delete_linux = answer
    typed = read_line(f"输入用户名 {name} 确认删除: ")
    if typed != name:
        print("已取消")
        return
    cmd_user_delete(NS(name=name, delete_linux=delete_linux))

def main_info_lines() -> list[str]:
    try:
        shares = len(SmbConf(SMB_CONF).load().shares())
    except NasError:
        shares = 0
    try:
        users = len(list_samba_users())
    except NasError:
        users = 0
    try:
        if discovery_enabled():
            discovery = "开"
            disco_name = discovery_state().get("netbios")
            if disco_name:
                discovery += f" ({disco_name})"
        else:
            discovery = "关"
    except NasError:
        discovery = "未配置"

    lines = [f"SMB    {shares} 个共享 · {users} 个用户 · 网络发现 {discovery}"]
    if zfs_available():
        lines.append(f"ZFS    {len(zfs_pools())} 个池")
    if shutil.which("lsblk"):
        try:
            disks = disk_list()
            lines.append(f"硬盘   {len(disks)} 块")
            hdds = [disk for disk in disks if disk["rota"]]
            space_cfg = load_space_config()
            space_alerts = load_space_alerts()
            if space_cfg.get("enabled") or space_alerts:
                if space_alerts:
                    names = "、".join(space_alert_label(key) for key in space_alerts)
                    lines.append(f"空间告警  {len(space_alerts)} 处（{names}）")
                else:
                    lines.append("空间监控  开启")
            if hdds:
                alerts = load_hdd_alerts()
                if not shutil.which("hdparm"):
                    lines.append("休眠   hdparm 未安装")
                else:
                    settings = load_hdd_sleep()
                    unset = []
                    for disk in hdds:
                        key = hdd_sleep_key(disk)
                        if key in alerts:
                            continue
                        value = settings.get(key, {})
                        try:
                            minutes = int(value.get("minutes", 0) or 0)
                        except (TypeError, ValueError):
                            minutes = 0
                        if minutes <= 0:
                            unset.append(disk["name"])
                    if unset:
                        lines.append(
                            f"休眠   {len(unset)} 块机械盘未设置（"
                            + "、".join(unset) + "）"
                        )
                    elif not alerts:
                        lines.append("休眠   机械盘已全部设置")
                if alerts:
                    names = [
                        item.get("name") or item.get("path") or "?"
                        for item in alerts.values()
                    ]
                    lines.append(
                        f"休眠保护  {len(alerts)} 块盘异常唤醒已取消（"
                        + "、".join(names) + "）"
                    )
        except NasError:
            pass
    try:
        auto = load_auto_snapshot()
        if auto["enabled"]:
            lines.append(
                f"快照   自动快照 {auto_snapshot_schedule_text(auto['oncalendar'])}"
                f" · 保留 {auto['keep'] or '不限'} 份 · {len(auto['datasets'])} 个数据集"
            )
    except NasError:
        pass
    if shutil.which("targetcli"):
        target_count = len(iscsi_targets())
        service = _service_state("rtslib-fb-targetctl")
        lines.append(f"iSCSI  {target_count} 块磁盘 · 服务 {service}")
    if zfs_available():
        try:
            encrypted = [row for row in zfs_encrypted_datasets()
                         if row.get("type") == "filesystem"]
        except NasError:
            encrypted = []
        if encrypted:
            locked = sum(1 for row in encrypted if row.get("keystatus") != "available")
            targets = iscsi_suspended_summary()[0] if shutil.which("targetcli") else []
            lines.append(
                f"加密  {len(encrypted)} 个数据集 · 未解锁 {locked}"
                f" · 隐藏 target {len(targets)}"
            )

    ip = ""
    proc = run(["hostname", "-I"], check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        ip = proc.stdout.split()[0]
    lines.insert(0, f"{os.uname().nodename}  {ip}".strip())
    return lines


def _interactive_raw() -> int:
    if not sys.stdin.isatty():
        print("nas 需要交互式终端（SSH 或本地控制台）。", file=sys.stderr)
        return 2

    # 备用屏幕缓冲区：退出时恢复原来的终端内容，而不是清屏
    sys.stdout.write("\033[?1049h\033[?25l")
    sys.stdout.flush()
    try:
        while True:
            items = list(MENU)
            items.append(("退出", "quit"))

            choice = select_one("nas — 主菜单", items, info=main_info_lines())
            if choice is None or choice == "quit":
                return 0

            try:
                HANDLERS[choice]()
            except NasError as exc:
                print(f"\n错误: {exc}")
            except KeyboardInterrupt:
                print("\n已取消")
    finally:
        sys.stdout.write("\033[?25h\033[?1049l")
        sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("nas 需要 root 权限运行。", file=sys.stderr)
        return 1
    if argv is None:
        self_install()
    if AUTO_SNAPSHOT:
        return auto_snapshot_run()
    if HDD_SLEEP:
        apply_hdd_sleep_settings()
    if HDD_MONITOR:
        return hdd_monitor()
    if BOOT_GUARD:
        return boot_guard()
    if HDD_SLEEP:
        return 0
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        if argv[0] in ("-h", "--help"):
            print("nas — 极简 Samba 共享管理（交互式）")
            print("直接运行：nas")
            print("环境变量：NAS_SMB_CONF / NAS_BACKUP_DIR / NAS_ROOTS / NAS_SKIP_RELOAD")
            print("开机保护：NAS_BOOT_GUARD=1 nas（由 systemd 调用）")
            print("权限：必须 root 运行")
            print("自安装：首次运行会安装；手动运行新版本会自动更新已安装脚本")
            return 0
        if argv[0] in ("-V", "--version"):
            print(f"nas {VERSION}")
            return 0
        print("nas 只提供交互界面；直接运行 nas", file=sys.stderr)
        return 2
    return interactive()


if __name__ == "__main__":
    sys.exit(main())
