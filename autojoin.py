import os
import re
import socket
import struct
import random
import threading
import time
import sys
import tkinter as tk
from tkinter import ttk, messagebox

# =============================
# A2S_INFO (Valve Source Query)
# =============================
A2S_INFO_REQUEST = b"\xFF\xFF\xFF\xFF" + b"TSource Engine Query\x00"


def _read_cstring(buf: bytes, offset: int) -> tuple[str, int]:
    end = buf.find(b"\x00", offset)
    if end == -1:
        raise ValueError("Malformed A2S response (missing cstring terminator).")
    return buf[offset:end].decode("utf-8", errors="replace"), end + 1


def a2s_info(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Minimal A2S_INFO implementation with challenge handling.
    Returns: dict(name, map, players, max_players, bots, id, game, folder, protocol)
    """
    addr = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    def _send(req: bytes) -> bytes:
        sock.sendto(req, addr)
        data, _ = sock.recvfrom(4096)
        return data

    try:
        data = _send(A2S_INFO_REQUEST)

        # Challenge response: 0xFFFFFFFF + 'A' + 4 bytes challenge
        if len(data) >= 9 and data[:4] == b"\xFF\xFF\xFF\xFF" and data[4:5] == b"A":
            challenge = data[5:9]
            data = _send(A2S_INFO_REQUEST + challenge)

        if len(data) < 6 or data[:4] != b"\xFF\xFF\xFF\xFF":
            raise ValueError("Invalid A2S response header.")
        if data[4:5] != b"I":
            raise ValueError(f"Unexpected A2S response type: {data[4:5]!r}")

        off = 5
        protocol = data[off]
        off += 1

        name, off = _read_cstring(data, off)
        map_name, off = _read_cstring(data, off)
        folder, off = _read_cstring(data, off)
        game, off = _read_cstring(data, off)

        if off + 2 > len(data):
            raise ValueError("Malformed A2S response (missing app id).")
        app_id = struct.unpack_from("<H", data, off)[0]
        off += 2

        if off + 3 > len(data):
            raise ValueError("Malformed A2S response (missing players/max/bots).")
        players = int(data[off])
        max_players = int(data[off + 1])
        bots = int(data[off + 2])

        return {
            "protocol": int(protocol),
            "name": name,
            "map": map_name,
            "folder": folder,
            "game": game,
            "id": int(app_id),
            "players": players,
            "max_players": max_players,
            "bots": bots,
        }
    finally:
        sock.close()


# =============================
# Input parsing
# =============================
CONNECT_RE = re.compile(
    r"^\s*(?:connect\s+)?(\d{1,3}(?:\.\d{1,3}){3})\s*:\s*(\d{1,5})\s*$",
    re.IGNORECASE
)


def parse_input(text: str) -> tuple[str, int]:
    """
    Accept:
      - 'connect 1.2.3.4:27015'
      - '1.2.3.4:27015'
    """
    m = CONNECT_RE.match(text)
    if not m:
        raise ValueError("请输入 IP:Port 或 connect IP:Port（例如：connect 123.123.123.123:27015）")

    ip = m.group(1)
    port = int(m.group(2))

    if not (1 <= port <= 65535):
        raise ValueError("端口必须在 1-65535 之间。")

    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError("IP 地址不合法。")
    for p in parts:
        try:
            n = int(p)
        except ValueError:
            raise ValueError("IP 地址不合法。")
        if not (0 <= n <= 255):
            raise ValueError("IP 地址不合法。")

    return ip, port


# =============================
# Steam launcher
# =============================
def open_steam_connect(app_id: int, ip: str, port: int) -> None:
    # Space must be URL-encoded as %20
    uri = f"steam://rungameid/{app_id}//+connect%20{ip}:{port}"

    if sys.platform.startswith("win"):
        os.startfile(uri)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        os.system(f'open "{uri}"')
    else:
        os.system(f'xdg-open "{uri}" >/dev/null 2>&1 &')


# =============================
# GUI App
# =============================
class JoinSniperApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CS 挤服工具 (A2S)")

        self.running = False
        self.worker_thread: threading.Thread | None = None
        self.last_trigger_ts = 0.0

        frm = ttk.Frame(root, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Address
        ttk.Label(frm, text="服务器地址：").grid(row=0, column=0, sticky="w")
        self.addr_var = tk.StringVar(value="connect 127.0.0.1:27015")
        self.addr_entry = ttk.Entry(frm, textvariable=self.addr_var, width=44)
        self.addr_entry.grid(row=0, column=1, columnspan=5, sticky="we", padx=(8, 0))
        frm.columnconfigure(1, weight=1)

        # Game select
        ttk.Label(frm, text="游戏：").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.game_var = tk.StringVar(value="cs2")
        self.game_combo = ttk.Combobox(
            frm, textvariable=self.game_var, state="readonly", values=["cs2", "css"], width=10
        )
        self.game_combo.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(10, 0))

        # Priority select (threshold)
        ttk.Label(frm, text="优先通道：").grid(row=1, column=2, sticky="e", padx=(12, 0), pady=(10, 0))
        self.priority_var = tk.StringVar(value="no")  # no / yes
        self.priority_combo = ttk.Combobox(
            frm, textvariable=self.priority_var, state="readonly", values=["no", "yes"], width=8
        )
        self.priority_combo.grid(row=1, column=3, sticky="w", padx=(8, 0), pady=(10, 0))
        ttk.Label(frm, text="(no→≥62, yes→≥64)").grid(row=1, column=4, sticky="w", pady=(10, 0))

        # Buttons
        self.start_btn = ttk.Button(frm, text="开始挤服", command=self.on_start)
        self.start_btn.grid(row=2, column=0, sticky="we", pady=(12, 0))

        self.stop_btn = ttk.Button(frm, text="停止", command=self.on_stop, state="disabled")
        self.stop_btn.grid(row=2, column=1, sticky="we", pady=(12, 0), padx=(8, 0))

        self.test_btn = ttk.Button(frm, text="测试 A2S", command=self.on_test)
        self.test_btn.grid(row=2, column=2, sticky="we", pady=(12, 0), padx=(8, 0))

        self.clear_btn = ttk.Button(frm, text="清空日志", command=self.on_clear)
        self.clear_btn.grid(row=2, column=3, sticky="we", pady=(12, 0), padx=(8, 0))

        # Status & log
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(frm, textvariable=self.status_var).grid(row=3, column=0, columnspan=6, sticky="w", pady=(10, 0))

        self.log = tk.Text(frm, height=14, width=90, state="disabled")
        self.log.grid(row=4, column=0, columnspan=6, sticky="nsew", pady=(8, 0))
        frm.rowconfigure(4, weight=1)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log_line(self, s: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts}] {s}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_status(self, s: str) -> None:
        self.status_var.set(s)

    def get_app_id(self) -> int:
        # CS2 -> 730, CS:S -> 240
        return 730 if self.game_var.get().strip().lower() == "cs2" else 240

    def get_start_threshold(self) -> int:
        # no priority => >=62 ; priority => >=64
        return 64 if self.priority_var.get().strip().lower() == "yes" else 62

    def set_controls_running(self, running: bool) -> None:
        if running:
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.addr_entry.configure(state="disabled")
            self.game_combo.configure(state="disabled")
            self.priority_combo.configure(state="disabled")
            self.test_btn.configure(state="disabled")
        else:
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.addr_entry.configure(state="normal")
            self.game_combo.configure(state="readonly")
            self.priority_combo.configure(state="readonly")
            self.test_btn.configure(state="normal")

    def on_clear(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def on_test(self) -> None:
        try:
            ip, port = parse_input(self.addr_var.get())
        except Exception as e:
            messagebox.showerror("输入错误", str(e))
            return

        self.set_status("A2S 测试中...")
        self.log_line(f"测试 A2S：{ip}:{port}")

        def _t():
            try:
                info = a2s_info(ip, port, timeout=1.0)
                self.root.after(0, lambda: self._show_test_result(info))
            except Exception as e:
                self.root.after(0, lambda: self._show_test_error(e))

        threading.Thread(target=_t, daemon=True).start()

    def _show_test_result(self, info: dict) -> None:
        self.set_status("A2S 测试成功")
        self.log_line(
            f"A2S_OK name='{info['name']}' map='{info['map']}' players={info['players']}/{info['max_players']} bots={info['bots']}"
        )

    def _show_test_error(self, e: Exception) -> None:
        self.set_status("A2S 测试失败")
        self.log_line(f"A2S_FAIL {e}")

    def on_start(self) -> None:
        if self.running:
            return

        try:
            ip, port = parse_input(self.addr_var.get())
        except Exception as e:
            messagebox.showerror("输入错误", str(e))
            return

        start_threshold = self.get_start_threshold()

        self.running = True
        self.set_controls_running(True)
        self.set_status("运行中：轮询 A2S...")
        self.log_line(
            f"开始：{ip}:{port} | game={self.game_var.get()} | interval=200-350ms | start_when_players>={start_threshold}"
        )

        self.worker_thread = threading.Thread(
            target=self.worker_loop,
            args=(ip, port, start_threshold),
            daemon=True
        )
        self.worker_thread.start()

    def on_stop(self) -> None:
        if not self.running:
            self.set_controls_running(False)
            return

        self.running = False
        self.set_controls_running(False)
        self.set_status("已停止")
        self.log_line("停止。")

        # 注意：输入框不清空（按你的要求）

    def on_close(self) -> None:
        self.running = False
        self.root.destroy()

    def worker_loop(self, ip: str, port: int, start_threshold: int) -> None:
        app_id = self.get_app_id()
        cooldown_sec = 2.0  # 仅用于防止同一瞬间多次触发（正常情况下触发后会立刻停止）

        while self.running:
            time.sleep(random.uniform(0.200, 0.350))

            try:
                info = a2s_info(ip, port, timeout=1.0)
                players = info["players"]
                max_players = info["max_players"]
                name = info.get("name", "")
                map_name = info.get("map", "")

                self.root.after(
                    0,
                    lambda p=players, m=max_players, n=name, mp=map_name: (
                        self.set_status(f"players={p}/{m} | map={mp}"),
                        self.log_line(f"A2S players={p}/{m} name='{n}'")
                    )
                )

                # 规则：达到阈值（>=62 或 >=64）就拉起，并立刻停止自动挤服
                if players < start_threshold:
                    now = time.time()
                    if now - self.last_trigger_ts >= cooldown_sec:
                        self.last_trigger_ts = now

                        self.root.after(
                            0,
                            lambda: self.log_line(
                                f"达到阈值：players({players}) < start({start_threshold})，拉起游戏并停止挤服..."
                            )
                        )

                        open_steam_connect(app_id, ip, port)

                        # 立刻停止：因为无法判断是否进服成功
                        self.running = False
                        self.root.after(0, self.on_stop)
                        break

            except Exception as e:
                self.root.after(0, lambda err=e: self.log_line(f"A2S_ERR {err}"))

        self.root.after(0, lambda: self.log_line("工作线程退出。"))


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    JoinSniperApp(root)
    root.minsize(840, 520)
    root.mainloop()


if __name__ == "__main__":
    main()
