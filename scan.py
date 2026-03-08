"""
Port Scanner - A multithreaded TCP/UDP port scanning tool with GUI
Version: 2.2  — Fully responsive layout (scrollable, scales to any screen)
"""

import socket
import threading
import datetime
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from queue import Queue

# --- Global state ---
results = {}
queue = Queue()
scan_running = False

# ─────────────────────────────────────────────
# THEME CONSTANTS
# ─────────────────────────────────────────────
BG_DARK    = "#0a0c10"
BG_MID     = "#111520"
BG_PANEL   = "#161b27"
ACCENT     = "#00ffe7"
ACCENT2    = "#7b5ea7"
RED_STOP   = "#e84545"
TXT_MAIN   = "#e2e8f0"
TXT_DIM    = "#6b7a99"
ENTRY_BG   = "#0d1117"
BORDER     = "#1f2d45"
FONT_MONO  = ("Courier New", 9)
FONT_UI    = ("Consolas", 9)
FONT_LABEL = ("Consolas", 9, "bold")
FONT_TITLE = ("Consolas", 13, "bold")


# ─────────────────────────────────────────────
# Core Scanning Functions
# ─────────────────────────────────────────────

def scan_port(host, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def scan_udp_port(host, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00", (host, port))
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except OSError:
            return "closed"


def get_service_name(port, protocol="tcp"):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


# ─────────────────────────────────────────────
# Multithreaded Scan Engine
# ─────────────────────────────────────────────

def thread_scan(host, port):
    timeout = float(entry_timeout.get()) if entry_timeout.get().replace(".", "").isdigit() else 1.0
    status = "open" if scan_port(host, port, timeout) else "closed"
    queue.put((port, status))


def process_queue():
    while not queue.empty():
        port, status = queue.get()
        results[port] = status


def scan_ports_multithreaded(host, start_port, end_port, max_threads=100):
    global scan_running
    scan_running = True
    threads = []
    total = end_port - start_port + 1

    for i, port in enumerate(range(start_port, end_port + 1)):
        if not scan_running:
            break
        while threading.active_count() > max_threads:
            pass
        t = threading.Thread(target=thread_scan, args=(host, port), daemon=True)
        threads.append(t)
        t.start()
        progress["value"] = int((i + 1) / total * 100)
        root.update_idletasks()

    for t in threads:
        t.join()

    process_queue()
    scan_running = False


# ─────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────

def generate_report(scan_results, show_closed=False):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = entry_host.get()
    resolved = resolve_host(host)

    lines = [
        f"╔══ PORT SCAN REPORT ══════════════════════════════╗",
        f"  Timestamp : {timestamp}",
        f"  Target    : {host}",
        f"  Resolved  : {resolved}",
        f"╠══════════════════════════════════════════════════╣",
    ]

    open_ports = 0
    for port in sorted(scan_results.keys()):
        status = scan_results[port]
        if status == "open":
            service = get_service_name(port)
            lines.append(f"  ▶  OPEN    {port:>5}/tcp   {service}")
            open_ports += 1
        elif show_closed:
            lines.append(f"  ·  closed  {port:>5}/tcp")

    lines += [
        f"╠══════════════════════════════════════════════════╣",
        f"  {open_ports} open port(s) found  /  {len(scan_results)} scanned",
        f"╚══════════════════════════════════════════════════╝",
    ]

    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    report_text.tag_configure("open",    foreground=ACCENT)
    report_text.tag_configure("closed",  foreground=TXT_DIM)
    report_text.tag_configure("header",  foreground=ACCENT2)
    report_text.tag_configure("summary", foreground="#f0a500")

    for line in lines:
        if "OPEN" in line:
            report_text.insert(tk.END, line + "\n", "open")
        elif "·  closed" in line:
            report_text.insert(tk.END, line + "\n", "closed")
        elif line.startswith("╔") or line.startswith("╚") or line.startswith("╠"):
            report_text.insert(tk.END, line + "\n", "header")
        elif "open port" in line:
            report_text.insert(tk.END, line + "\n", "summary")
        else:
            report_text.insert(tk.END, line + "\n")

    report_text.config(state=tk.DISABLED)


def export_report():
    content = report_text.get(1.0, tk.END).strip()
    if not content:
        messagebox.showwarning("Empty report", "No report to export yet.")
        return
    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Save report as...",
    )
    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Export", f"Report saved to:\n{filepath}")


# ─────────────────────────────────────────────
# GUI Callbacks
# ─────────────────────────────────────────────

def _launch_tcp_scan(host, start_port, end_port):
    results.clear()
    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    report_text.config(state=tk.DISABLED)
    progress["value"] = 0

    btn_scan_tcp.config(state=tk.DISABLED)
    btn_scan_all.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    lbl_status.config(text=f"⟳  Scanning {host}  [{start_port} → {end_port}]", fg=ACCENT)

    port_count = end_port - start_port + 1
    max_threads = min(500, max(100, port_count // 130))

    def run():
        scan_ports_multithreaded(host, start_port, end_port, max_threads=max_threads)
        show_closed = var_show_closed.get()
        generate_report(results, show_closed=show_closed)
        btn_scan_tcp.config(state=tk.NORMAL)
        btn_scan_all.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)
        progress["value"] = 100
        open_count = sum(1 for s in results.values() if s == "open")
        lbl_status.config(
            text=f"✔  Done — {open_count} open / {len(results)} scanned",
            fg=ACCENT
        )

    threading.Thread(target=run, daemon=True).start()


def scan_tcp():
    host = entry_host.get().strip()
    start_str = entry_start_port.get().strip()
    end_str = entry_end_port.get().strip()

    if not host:
        messagebox.showerror("Error", "Please enter a target host or IP address.")
        return
    if not (start_str.isdigit() and end_str.isdigit()):
        messagebox.showerror("Error", "Please enter valid integer port numbers.")
        return

    start_port, end_port = int(start_str), int(end_str)

    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        messagebox.showerror("Error", "Ports must be between 0 and 65535.")
        return
    if start_port > end_port:
        messagebox.showerror("Error", "Start port must be <= end port.")
        return

    _launch_tcp_scan(host, start_port, end_port)


def scan_all_ports():
    host = entry_host.get().strip()
    if not host:
        messagebox.showerror("Error", "Please enter a target host or IP address.")
        return
    confirm = messagebox.askyesno(
        "Full scan - 65 536 ports",
        f"You are about to scan ALL 65 536 TCP ports on:\n\n  {host}\n\n"
        "This may take several minutes depending on the timeout and network.\n\nContinue?",
    )
    if not confirm:
        return
    entry_start_port.delete(0, tk.END)
    entry_start_port.insert(0, "0")
    entry_end_port.delete(0, tk.END)
    entry_end_port.insert(0, "65535")
    _launch_tcp_scan(host, 0, 65535)


def set_preset(start, end):
    entry_start_port.delete(0, tk.END)
    entry_start_port.insert(0, str(start))
    entry_end_port.delete(0, tk.END)
    entry_end_port.insert(0, str(end))
    host = entry_host.get().strip()
    if not host:
        messagebox.showerror("Error", "Please enter a target host or IP address first.")
        return
    _launch_tcp_scan(host, start, end)


def stop_scan():
    global scan_running
    scan_running = False
    btn_stop.config(state=tk.DISABLED)
    lbl_status.config(text="⚠  Scan aborted by user.", fg=RED_STOP)


def scan_udp():
    host = entry_host.get().strip()
    udp_str = entry_udp_port.get().strip()
    if not host:
        messagebox.showerror("Error", "Please enter a target host or IP address.")
        return
    if not udp_str.isdigit():
        messagebox.showerror("Error", "Please enter a valid port number.")
        return
    port = int(udp_str)
    status = scan_udp_port(host, port)
    service = get_service_name(port, "udp")
    messagebox.showinfo("UDP Scan Result", f"Port UDP {port} ({service}): {status.upper()}")


def create_report():
    if not results:
        messagebox.showwarning("No data", "Run a scan first.")
        return
    generate_report(results, show_closed=var_show_closed.get())


# ─────────────────────────────────────────────
# Helper: styled widgets
# ─────────────────────────────────────────────

def styled_entry(parent, width=20, **kw):
    return tk.Entry(
        parent, width=width,
        bg=ENTRY_BG, fg=TXT_MAIN,
        insertbackground=ACCENT,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        font=FONT_UI,
        **kw,
    )


def styled_label(parent, text, dim=False, **kw):
    return tk.Label(
        parent, text=text,
        bg=BG_PANEL,
        fg=TXT_DIM if dim else TXT_MAIN,
        font=FONT_LABEL,
        **kw,
    )


def styled_button(parent, text, cmd, color=ACCENT, width=16, state=tk.NORMAL):
    return tk.Button(
        parent, text=text, command=cmd,
        width=width,
        bg="#1a2235", fg=color,
        activebackground="#243050", activeforeground=color,
        relief=tk.FLAT,
        bd=0,
        highlightthickness=1,
        highlightbackground=color,
        font=FONT_LABEL,
        cursor="hand2",
        state=state,
        pady=5,
    )


def styled_labelframe(parent, text):
    return tk.LabelFrame(
        parent, text=f"  {text}  ",
        bg=BG_PANEL,
        fg=ACCENT,
        font=FONT_LABEL,
        bd=1,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=BORDER,
        padx=10, pady=6,
    )


# ─────────────────────────────────────────────
# Scrollable main frame setup
# ─────────────────────────────────────────────

root = tk.Tk()
root.title("PORT SCANNER  v2.2")
root.configure(bg=BG_DARK)
root.minsize(520, 400)

# Use screen dimensions for a sensible default size
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
win_w = min(860, int(sw * 0.65))
win_h = min(900, int(sh * 0.85))
root.geometry(f"{win_w}x{win_h}")

# ── ttk styles ──
style = ttk.Style()
style.theme_use("default")
style.configure(
    "Cyber.Horizontal.TProgressbar",
    troughcolor=ENTRY_BG,
    background=ACCENT,
    darkcolor=ACCENT,
    lightcolor=ACCENT,
    bordercolor=BORDER,
    thickness=6,
)
style.configure("Dark.Vertical.TScrollbar",
    background=BG_MID,
    troughcolor=ENTRY_BG,
    arrowcolor=TXT_DIM,
    bordercolor=BORDER,
)

PAD = {"padx": 10, "pady": 4}

# ── Title bar (fixed at top, never scrolls) ──
title_bar = tk.Frame(root, bg=BG_MID, pady=8)
title_bar.pack(fill=tk.X, side=tk.TOP)

tk.Label(
    title_bar, text="▐ PORT SCANNER v2.2",
    bg=BG_MID, fg=ACCENT, font=FONT_TITLE,
).pack(side=tk.LEFT, padx=16)
tk.Label(
    title_bar, text="TCP · UDP · Multithreaded",
    bg=BG_MID, fg=TXT_DIM, font=("Consolas", 8),
).pack(side=tk.LEFT)

# ── Scrollable canvas region ──
canvas_outer = tk.Canvas(root, bg=BG_DARK, highlightthickness=0)
vscroll = ttk.Scrollbar(root, orient="vertical", command=canvas_outer.yview,
                         style="Dark.Vertical.TScrollbar")
canvas_outer.configure(yscrollcommand=vscroll.set)

vscroll.pack(side=tk.RIGHT, fill=tk.Y)
canvas_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

inner = tk.Frame(canvas_outer, bg=BG_DARK)
canvas_window = canvas_outer.create_window((0, 0), window=inner, anchor="nw")


def _on_frame_configure(event):
    canvas_outer.configure(scrollregion=canvas_outer.bbox("all"))


def _on_canvas_configure(event):
    canvas_outer.itemconfig(canvas_window, width=event.width)


inner.bind("<Configure>", _on_frame_configure)
canvas_outer.bind("<Configure>", _on_canvas_configure)

# Mouse-wheel scrolling (cross-platform)
def _on_mousewheel(event):
    if event.num == 4:
        canvas_outer.yview_scroll(-1, "units")
    elif event.num == 5:
        canvas_outer.yview_scroll(1, "units")
    else:
        canvas_outer.yview_scroll(int(-1 * (event.delta / 120)), "units")

canvas_outer.bind_all("<MouseWheel>", _on_mousewheel)
canvas_outer.bind_all("<Button-4>",   _on_mousewheel)
canvas_outer.bind_all("<Button-5>",   _on_mousewheel)


# ─────────────────────────────────────────────
# GUI Layout  (all packed inside `inner`)
# ─────────────────────────────────────────────

# ── TARGET ──
frame_target = styled_labelframe(inner, "TARGET")
frame_target.pack(fill=tk.X, **PAD)

styled_label(frame_target, "Host / IP :").grid(row=0, column=0, sticky="w", pady=2)
entry_host = styled_entry(frame_target, width=34)
entry_host.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=2)

styled_label(frame_target, "Timeout (s) :").grid(row=1, column=0, sticky="w", pady=2)
entry_timeout = styled_entry(frame_target, width=7)
entry_timeout.insert(0, "1.0")
entry_timeout.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=2)

frame_target.columnconfigure(1, weight=1)

# ── TCP SCAN ──
frame_tcp = styled_labelframe(inner, "TCP SCAN")
frame_tcp.pack(fill=tk.X, **PAD)

styled_label(frame_tcp, "Start port :").grid(row=0, column=0, sticky="w", pady=2)
entry_start_port = styled_entry(frame_tcp, width=9)
entry_start_port.grid(row=0, column=1, sticky="w", padx=(8, 0), pady=2)

styled_label(frame_tcp, "End port :").grid(row=1, column=0, sticky="w", pady=2)
entry_end_port = styled_entry(frame_tcp, width=9)
entry_end_port.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=2)

frame_presets = tk.Frame(frame_tcp, bg=BG_PANEL)
frame_presets.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 2))

styled_label(frame_presets, "Presets :").pack(side=tk.LEFT, padx=(0, 6))

PRESETS = [
    ("0-1023",        0,     1023),
    ("1024-49151",    1024,  49151),
    ("49152-65535",   49152, 65535),
    ("Common 20-443", 20,    443),
]
for label, s, e in PRESETS:
    btn = tk.Button(
        frame_presets, text=label,
        font=("Consolas", 8),
        bg=ENTRY_BG, fg=TXT_DIM,
        activebackground="#243050", activeforeground=ACCENT,
        relief=tk.FLAT, bd=0,
        highlightthickness=1, highlightbackground=BORDER,
        cursor="hand2", padx=6, pady=3,
        command=lambda s=s, e=e: set_preset(s, e),
    )
    btn.pack(side=tk.LEFT, padx=3)

var_show_closed = tk.BooleanVar(value=False)
chk = tk.Checkbutton(
    frame_tcp, text="Show closed ports",
    variable=var_show_closed,
    bg=BG_PANEL, fg=TXT_DIM,
    selectcolor=ENTRY_BG,
    activebackground=BG_PANEL,
    activeforeground=ACCENT,
    font=FONT_UI,
)
chk.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

# ── UDP SCAN ──
frame_udp = styled_labelframe(inner, "UDP SCAN  (single port)")
frame_udp.pack(fill=tk.X, **PAD)

styled_label(frame_udp, "UDP port :").grid(row=0, column=0, sticky="w")
entry_udp_port = styled_entry(frame_udp, width=9)
entry_udp_port.grid(row=0, column=1, sticky="w", padx=(8, 0))

# ── Status ──
lbl_status = tk.Label(
    inner, text="●  READY",
    anchor="w",
    bg=BG_DARK, fg=TXT_DIM,
    font=("Consolas", 9),
)
lbl_status.pack(fill=tk.X, padx=12, pady=(6, 0))

# ── Progress bar ──
progress = ttk.Progressbar(
    inner, orient="horizontal",
    mode="determinate",
    style="Cyber.Horizontal.TProgressbar",
)
progress.pack(fill=tk.X, padx=10, pady=(2, 6))

# ── Report ──
frame_report = styled_labelframe(inner, "REPORT")
frame_report.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

report_text = tk.Text(
    frame_report, height=14, width=60,
    state=tk.DISABLED,
    bg="#060a0f", fg=TXT_MAIN,
    font=FONT_MONO,
    relief=tk.FLAT,
    insertbackground=ACCENT,
    selectbackground=ACCENT2,
    selectforeground="#ffffff",
    bd=0,
)
scrollbar_report = ttk.Scrollbar(frame_report, orient="vertical", command=report_text.yview)
report_text.configure(yscrollcommand=scrollbar_report.set)
report_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar_report.pack(side=tk.RIGHT, fill=tk.Y)

# ── Button rows ──
frame_btns = tk.Frame(inner, bg=BG_DARK)
frame_btns.pack(fill=tk.X, padx=10, pady=8)

# Row 0 – scan controls
btn_scan_tcp = styled_button(frame_btns, "▶  Scan TCP", scan_tcp, color=ACCENT, width=16)
btn_scan_tcp.grid(row=0, column=0, padx=5, pady=3, sticky="ew")

btn_scan_all = styled_button(
    frame_btns, "▶▶  Scan ALL (0-65535)",
    scan_all_ports, color=ACCENT2, width=24)
btn_scan_all.grid(row=0, column=1, padx=5, pady=3, sticky="ew")

btn_stop = styled_button(frame_btns, "■  Stop", stop_scan, color=RED_STOP, width=10, state=tk.DISABLED)
btn_stop.grid(row=0, column=2, padx=5, pady=3, sticky="ew")

# Row 1 – utilities
btn_scan_udp = styled_button(frame_btns, "▶  Scan UDP", scan_udp, color="#f0a500", width=16)
btn_scan_udp.grid(row=1, column=0, padx=5, pady=3, sticky="ew")

btn_report = styled_button(frame_btns, "⟳  Refresh report", create_report, color=TXT_DIM, width=18)
btn_report.grid(row=1, column=1, padx=5, pady=3, sticky="ew")

btn_export = styled_button(frame_btns, "↓  Export .txt", export_report, color=TXT_DIM, width=14)
btn_export.grid(row=1, column=2, padx=5, pady=3, sticky="ew")

btn_quit = styled_button(frame_btns, "✕  Quit", root.quit, color=RED_STOP, width=10)
btn_quit.grid(row=1, column=3, padx=5, pady=3, sticky="ew")

# Allow button columns to expand evenly
for col in range(4):
    frame_btns.columnconfigure(col, weight=1)

# ── Footer ──
tk.Label(
    inner,
    text="Use responsibly — only scan systems you are authorised to test.",
    bg=BG_DARK, fg="#2a3550",
    font=("Consolas", 7),
).pack(pady=(0, 6))

root.mainloop()
