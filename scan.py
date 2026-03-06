"""
Port Scanner - A multithreaded TCP/UDP port scanning tool with GUI
Author: [Your Name]
Version: 2.1
Description:
    This tool allows scanning TCP and UDP ports on a target host.
    It features a Tkinter-based graphical interface, multithreaded scanning,
    service name resolution, and report export functionality.
"""

import socket
import threading
import datetime
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from queue import Queue

# --- Global state ---

results = {}        # Stores port scan results: { port: status }
queue = Queue()     # Thread-safe queue to collect results from worker threads
scan_running = False  # Flag to allow scan cancellation


# ---------------------------------------------
# Core Scanning Functions
# ---------------------------------------------

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempt a TCP connection to a given host and port.

    Args:
        host: Target IP address or hostname.
        port: Port number to probe.
        timeout: Connection timeout in seconds (default: 1.0).

    Returns:
        True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def scan_udp_port(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt a UDP probe to a given host and port.

    UDP scanning is inherently unreliable: no response may mean open|filtered.

    Args:
        host: Target IP address or hostname.
        port: Port number to probe.
        timeout: Socket timeout in seconds (default: 1.0).

    Returns:
        'open' if a response is received,
        'closed' if an ICMP port-unreachable is received,
        'open|filtered' if no response (timeout).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00", (host, port))
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            # No response: port may be open or silently filtered
            return "open|filtered"
        except OSError:
            # ICMP port unreachable -> port is closed
            return "closed"


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Resolve the well-known service name for a port number.

    Args:
        port: Port number.
        protocol: 'tcp' or 'udp'.

    Returns:
        Service name string, or 'Unknown' if not found.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"


def resolve_host(host: str) -> str:
    """
    Resolve a hostname to an IP address.

    Args:
        host: Hostname or IP string.

    Returns:
        Resolved IP address string, or the original string on failure.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


# ---------------------------------------------
# Multithreaded Scan Engine
# ---------------------------------------------

def thread_scan(host: str, port: int):
    """
    Worker function executed by each scanning thread.
    Pushes result tuple (port, status) into the shared queue.

    Args:
        host: Target host.
        port: Port to scan.
    """
    timeout = float(entry_timeout.get()) if entry_timeout.get().replace(".", "").isdigit() else 1.0
    status = "open" if scan_port(host, port, timeout) else "closed"
    queue.put((port, status))


def process_queue():
    """Drain the result queue and store results in the global dict."""
    while not queue.empty():
        port, status = queue.get()
        results[port] = status


def scan_ports_multithreaded(host: str, start_port: int, end_port: int, max_threads: int = 100):
    """
    Launch multithreaded TCP scan over a port range.

    Throttles thread creation to stay under max_threads at any time.
    Processes the result queue after all threads complete.

    Args:
        host: Target host.
        start_port: First port in range.
        end_port: Last port in range (inclusive).
        max_threads: Maximum concurrent threads (default: 100).
    """
    global scan_running
    scan_running = True
    threads = []
    total = end_port - start_port + 1

    for i, port in enumerate(range(start_port, end_port + 1)):
        if not scan_running:
            break  # Honour cancellation request

        # Throttle: wait if too many threads are active
        while threading.active_count() > max_threads:
            pass

        t = threading.Thread(target=thread_scan, args=(host, port), daemon=True)
        threads.append(t)
        t.start()

        # Update progress bar
        progress["value"] = int((i + 1) / total * 100)
        root.update_idletasks()

    for t in threads:
        t.join()

    process_queue()
    scan_running = False


# ---------------------------------------------
# Report Generation
# ---------------------------------------------

def generate_report(scan_results: dict, show_closed: bool = False):
    """
    Render scan results into the report text area.

    Args:
        scan_results: Dict mapping port numbers to their status strings.
        show_closed: If True, closed ports are included (default: False).
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = entry_host.get()
    resolved = resolve_host(host)

    lines = [
        f"Port Scan Report - {timestamp}",
        f"Target : {host} ({resolved})",
        "=" * 50,
    ]

    open_ports = 0
    for port in sorted(scan_results.keys()):
        status = scan_results[port]
        if status == "open":
            service = get_service_name(port)
            lines.append(f"  [OPEN]   Port {port:>5}  -  {service}")
            open_ports += 1
        elif show_closed:
            lines.append(f"  [closed] Port {port:>5}")

    lines += ["=" * 50, f"Summary: {open_ports} open port(s) found out of {len(scan_results)} scanned."]

    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    report_text.insert(tk.END, "\n".join(lines))
    report_text.config(state=tk.DISABLED)


def export_report():
    """Save the current report text to a .txt file chosen by the user."""
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


# ---------------------------------------------
# GUI Callbacks
# ---------------------------------------------

def _launch_tcp_scan(host: str, start_port: int, end_port: int):
    """
    Internal helper: clear state, update UI and start the background scan thread.

    Args:
        host: Validated target host string.
        start_port: First port to scan.
        end_port: Last port to scan (inclusive).
    """
    results.clear()
    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    report_text.config(state=tk.DISABLED)
    progress["value"] = 0

    # Disable scan buttons, enable Stop
    btn_scan_tcp.config(state=tk.DISABLED)
    btn_scan_all.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)

    # Show scan scope in status label
    lbl_status.config(text=f"Scanning {host}  ports {start_port}-{end_port}...")

    # Choose thread count: more threads for large ranges (capped at 500)
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
        lbl_status.config(text=f"Done - {open_count} open port(s) found out of {len(results)} scanned.")

    threading.Thread(target=run, daemon=True).start()


def scan_tcp():
    """
    Validate manual port-range inputs and launch a TCP scan.
    Called by the ' Scan TCP' button.
    """
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
    """
    Scan the full TCP port space (0-65535).
    Called by the ' Scan ALL ports' button.
    Asks for confirmation because scanning 65 536 ports takes time.
    """
    host = entry_host.get().strip()
    if not host:
        messagebox.showerror("Error", "Please enter a target host or IP address.")
        return

    confirm = messagebox.askyesno(
        "Full scan - 65 536 ports",
        f"You are about to scan ALL 65 536 TCP ports on:\n\n  {host}\n\n"
        "This may take several minutes depending on the timeout and network.\n\n"
        "Continue?",
    )
    if not confirm:
        return

    # Pre-fill the range fields for visibility
    entry_start_port.delete(0, tk.END)
    entry_start_port.insert(0, "0")
    entry_end_port.delete(0, tk.END)
    entry_end_port.insert(0, "65535")

    _launch_tcp_scan(host, 0, 65535)


def set_preset(start: int, end: int):
    """
    Fill the port range fields with a preset and trigger a TCP scan.

    Args:
        start: Start port of the preset range.
        end: End port of the preset range.
    """
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
    """Request cancellation of the running scan."""
    global scan_running
    scan_running = False
    btn_stop.config(state=tk.DISABLED)


def scan_udp():
    """Validate input and perform a UDP probe on a single port."""
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
    """Re-render the report from current results (useful after toggling options)."""
    if not results:
        messagebox.showwarning("No data", "Run a scan first.")
        return
    generate_report(results, show_closed=var_show_closed.get())


# ---------------------------------------------
# GUI Layout
# ---------------------------------------------

root = tk.Tk()
root.title("Port Scanner v2.1")
root.resizable(True, True)

# -- Simple frame, no canvas, no blank space
inner = tk.Frame(root)
inner.pack(fill=tk.BOTH, expand=True)

PAD = {"padx": 8, "pady": 3}

# -- Target frame
frame_target = tk.LabelFrame(inner, text="Target", padx=8, pady=4)
frame_target.grid(row=0, column=0, columnspan=2, sticky="ew", **PAD)

tk.Label(frame_target, text="Host / IP :").grid(row=0, column=0, sticky="w")
entry_host = tk.Entry(frame_target, width=30)
entry_host.grid(row=0, column=1, sticky="ew", padx=4)

tk.Label(frame_target, text="Timeout (s) :").grid(row=1, column=0, sticky="w")
entry_timeout = tk.Entry(frame_target, width=6)
entry_timeout.insert(0, "1.0")
entry_timeout.grid(row=1, column=1, sticky="w", padx=4)

# -- TCP frame
frame_tcp = tk.LabelFrame(inner, text="TCP Scan", padx=8, pady=4)
frame_tcp.grid(row=1, column=0, columnspan=2, sticky="ew", **PAD)

tk.Label(frame_tcp, text="Start port :").grid(row=0, column=0, sticky="w")
entry_start_port = tk.Entry(frame_tcp, width=8)
entry_start_port.grid(row=0, column=1, sticky="w", padx=4)

tk.Label(frame_tcp, text="End port :").grid(row=1, column=0, sticky="w")
entry_end_port = tk.Entry(frame_tcp, width=8)
entry_end_port.grid(row=1, column=1, sticky="w", padx=4)

# -- Preset range buttons
frame_presets = tk.Frame(frame_tcp)
frame_presets.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

tk.Label(frame_presets, text="Presets :").pack(side=tk.LEFT)

PRESETS = [
    ("Well-known (0-1023)",     0,     1023),
    ("Registered (1024-49151)", 1024, 49151),
    ("Dynamic (49152-65535)",   49152, 65535),
    ("Common (20-443)",         20,    443),
]
for label, s, e in PRESETS:
    tk.Button(
        frame_presets, text=label, font=("TkDefaultFont", 8),
        command=lambda s=s, e=e: set_preset(s, e)
    ).pack(side=tk.LEFT, padx=2)

var_show_closed = tk.BooleanVar(value=False)
tk.Checkbutton(frame_tcp, text="Show closed ports", variable=var_show_closed).grid(
    row=3, column=0, columnspan=3, sticky="w"
)

# -- UDP frame
frame_udp = tk.LabelFrame(inner, text="UDP Scan (single port)", padx=8, pady=4)
frame_udp.grid(row=2, column=0, columnspan=2, sticky="ew", **PAD)

tk.Label(frame_udp, text="UDP port :").grid(row=0, column=0, sticky="w")
entry_udp_port = tk.Entry(frame_udp, width=8)
entry_udp_port.grid(row=0, column=1, sticky="w", padx=4)

# -- Status label
lbl_status = tk.Label(inner, text="Ready.", anchor="w", fg="#555555")
lbl_status.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8)

# -- Progress bar
progress = ttk.Progressbar(inner, orient="horizontal", length=400, mode="determinate")
progress.grid(row=4, column=0, columnspan=2, **PAD)

# -- Report area (shorter height to leave room for buttons)
report_text = tk.Text(inner, height=10, width=58, state=tk.DISABLED,
                      bg="#1e1e1e", fg="#d4d4d4", font=("Courier New", 9))
scrollbar_report = ttk.Scrollbar(inner, orient="vertical", command=report_text.yview)
report_text.configure(yscrollcommand=scrollbar_report.set)
report_text.grid(row=5, column=0, sticky="nsew", **PAD)
scrollbar_report.grid(row=5, column=1, sticky="ns", pady=3)

# -- Button row
frame_btns = tk.Frame(inner)
frame_btns.grid(row=6, column=0, columnspan=2, pady=6)

btn_scan_tcp = tk.Button(frame_btns, text="Scan TCP", command=scan_tcp, width=16, bg="#0078d4", fg="white")
btn_scan_tcp.grid(row=0, column=0, padx=4, pady=2)

btn_scan_all = tk.Button(
    frame_btns, text="Scan ALL ports (0-65535)",
    command=scan_all_ports, width=26, bg="#6a0dad", fg="white"
)
btn_scan_all.grid(row=0, column=1, padx=4, pady=2)

btn_stop = tk.Button(frame_btns, text="Stop", command=stop_scan, width=10, state=tk.DISABLED)
btn_stop.grid(row=0, column=2, padx=4, pady=2)

btn_scan_udp = tk.Button(frame_btns, text="Scan UDP", command=scan_udp, width=16)
btn_scan_udp.grid(row=1, column=0, padx=4, pady=2)

btn_report = tk.Button(frame_btns, text="Refresh report", command=create_report, width=16)
btn_report.grid(row=1, column=1, padx=4, pady=2)

btn_export = tk.Button(frame_btns, text="Export .txt", command=export_report, width=14)
btn_export.grid(row=1, column=2, padx=4, pady=2)

btn_quit = tk.Button(frame_btns, text="Quit", command=root.quit, width=10, bg="#c0392b", fg="white")
btn_quit.grid(row=1, column=3, padx=4, pady=2)

# -- Launch
root.mainloop()
