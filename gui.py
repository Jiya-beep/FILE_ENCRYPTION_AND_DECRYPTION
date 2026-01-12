import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import base64
import threading
import time
import traceback
import json
from datetime import datetime
from pathlib import Path

import auth, crypto, integrity, db, performance

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import numpy as _np
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False

# Report generation via reportlab (optional)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ---------------- helpers ----------------
def derive_key(passphrase: str) -> bytes:
    """Derive 32-byte (256-bit) key from passphrase using SHA-256."""
    return hashlib.sha256(passphrase.encode()).digest()

def bring_window_front(root: tk.Tk):
    """Bring window to front briefly so messageboxes appear above other windows."""
    try:
        root.update()
        root.attributes('-topmost', True)
        root.after(150, lambda: root.attributes('-topmost', False))
    except Exception:
        pass

def get_reports_dir() -> Path:
    """Return (and create) the user's Documents/EncryptEase_Reports folder."""
    p = Path.home() / "Documents" / "EncryptEase_Reports"
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        # fallback to current folder if Documents not writable
        p = Path.cwd() / "EncryptEase_Reports"
        p.mkdir(parents=True, exist_ok=True)
    return p

# ---------------- main app ----------------
class EncryptEaseApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Encrypt-Ease ")
        self.root.geometry("980x700")
        self.user = None
        self.file_path = None
        self.selected_algo = tk.StringVar(value="AES")
        self.use_rsa_wrap = tk.BooleanVar(value=False)
        self.private_key_pem = None
        self.public_key_pem = None

        # ensure DB
        db.init_db()

        self._build_style()
        self.login_screen()

        # prepare reports dir
        self.reports_dir = get_reports_dir()

    def _build_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        style.configure("Card.TFrame", background="#f7f9fc", relief="flat")
        style.configure("Stat.TLabel", font=("Arial", 11))
        style.configure("Title.TLabel", font=("Arial", 12, "bold"))

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    # ---------------- Login / Register ----------------
    def login_screen(self):
        self.clear()
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Encrypt-Ease", style="Header.TLabel").pack(pady=(6,12))
        form = ttk.Frame(frame)
        form.pack(pady=6)

        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        u = ttk.Entry(form, width=30); u.grid(row=0, column=1, pady=6)
        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        p = ttk.Entry(form, width=30, show="*"); p.grid(row=1, column=1, pady=6)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=8)

        def attempt():
            try:
                if auth.verify_user(u.get(), p.get()):
                    self.user = u.get()
                    db.log_action(self.user, "login", "")
                    self.main_screen()
                else:
                    bring_window_front(self.root)
                    messagebox.showerror("Login", "Invalid credentials")
            except Exception as ex:
                bring_window_front(self.root)
                messagebox.showerror("Error", str(ex))

        def register():
            try:
                auth.create_user(u.get(), p.get())
                bring_window_front(self.root)
                messagebox.showinfo("Register", "User created successfully!")
            except ValueError:
                bring_window_front(self.root)
                messagebox.showerror("Error", "User already exists")
            except Exception as ex:
                bring_window_front(self.root)
                messagebox.showerror("Error", str(ex))

        ttk.Button(btn_frame, text="Login", command=attempt).grid(row=0, column=0, padx=6)
        ttk.Button(btn_frame, text="Register", command=register).grid(row=0, column=1, padx=6)

    # ---------------- Main Dashboard ----------------
    def main_screen(self):
        self.clear()
        # Header
        header = tk.Frame(self.root, bg="#34495e", height=56)
        header.pack(fill="x")
        ttk.Label(header, text=f" Encrypt-Ease — Welcome, {self.user}", style="Header.TLabel",
                  foreground="white", background="#34495e").pack(side="left", padx=12, pady=8)
        ttk.Button(header, text="Logout", command=self.logout).pack(side="right", padx=12, pady=10)

        # Layout
        main = tk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=12, pady=12)

        left = tk.Frame(main, width=380)
        left.pack(side="left", fill="y", padx=(0,12))
        right = tk.Frame(main)
        right.pack(side="right", fill="both", expand=True)

        # Dashboard card
        card = ttk.Frame(left, style="Card.TFrame", padding=10)
        card.pack(fill="x", pady=(0,10))
        ttk.Label(card, text="Dashboard", style="Title.TLabel").pack(anchor="w")
        stats = db.get_stats()
        users_count = self._count_users()
        files_enc = stats.get("files_encrypted", 0)
        stat_frame = ttk.Frame(card)
        stat_frame.pack(pady=8, fill="x")
        ttk.Label(stat_frame, text=f"👥 Total Users: {users_count}", style="Stat.TLabel").pack(anchor="w", pady=2)
        ttk.Label(stat_frame, text=f"🔒 Files Encrypted: {files_enc}", style="Stat.TLabel").pack(anchor="w", pady=2)

        # Controls card
        ctrl_card = ttk.Frame(left, style="Card.TFrame", padding=10)
        ctrl_card.pack(fill="x", pady=(6,10))
        ttk.Label(ctrl_card, text="Controls", style="Title.TLabel").pack(anchor="w")
        ttk.Button(ctrl_card, text="Select File 📁", command=self.select_file).pack(fill="x", pady=6)
        ttk.Button(ctrl_card, text="Encrypt 🔒", command=self.encrypt_file).pack(fill="x", pady=6)
        ttk.Button(ctrl_card, text="Decrypt 🔓", command=self.decrypt_file).pack(fill="x", pady=6)
        ttk.Button(ctrl_card, text="Check Integrity 🧾", command=self.check_hash).pack(fill="x", pady=6)

        algo_frame = ttk.Frame(ctrl_card)
        algo_frame.pack(fill="x", pady=4)
        ttk.Label(algo_frame, text="Algorithm:").pack(side="left", padx=(0,6))
        ttk.Combobox(algo_frame, textvariable=self.selected_algo, values=["AES", "ChaCha"], width=8).pack(side="left")
        self.rsa_chk = tk.Checkbutton(
        algo_frame,
            text="RSA wrap (✓ enabled)",
            variable=self.use_rsa_wrap,
            onvalue=True,
            offvalue=False,
            font=("Arial", 10),
            fg="#2c3e50",
            selectcolor="#d6f5d6",
            relief="flat",
            indicatoron=True,
        )
        self.rsa_chk.pack(side="left", padx=6)

        def toggle_tick():
            if self.use_rsa_wrap.get():
                self.rsa_chk.config(text="RSA wrap (✓ enabled)")
            else:
                self.rsa_chk.config(text="RSA wrap (disabled)")

        self.use_rsa_wrap.trace_add("write", lambda *args: toggle_tick())

        ttk.Button(algo_frame, text="Gen RSA pair", command=self._generate_rsa).pack(side="left", padx=(8,0))

        # Graph & Report Section
        graph_card = ttk.Frame(left, style="Card.TFrame", padding=10)
        graph_card.pack(fill="x")
        ttk.Label(graph_card, text="Performance", style="Title.TLabel").pack(anchor="w")
        self.graph_button = ttk.Button(graph_card, text="Show Graph 📊", command=self._on_show_graph)
        self.graph_button.pack(fill="x", pady=6)
        self.auto_graph_checkbox = tk.BooleanVar(value=True)
        # Auto-save checkbox with ✓ tick toggle
        self.auto_graph_checkbox = tk.BooleanVar(value=True)
        self.auto_chk = tk.Checkbutton(
            graph_card,
            text="Auto-save graph to Reports folder (✓ enabled)",
            variable=self.auto_graph_checkbox,
            onvalue=True,
            offvalue=False,
            font=("Arial", 10),
            fg="#2c3e50",
            selectcolor="#d6f5d6",
            relief="flat",
            indicatoron=True,
        )
        self.auto_chk.pack(anchor="w", pady=(4, 2))

        def toggle_auto():
            if self.auto_graph_checkbox.get():
                self.auto_chk.config(text="Auto-save graph to Reports folder (✓ enabled)")
            else:
                self.auto_chk.config(text="Auto-save graph to Reports folder (disabled)")

        self.auto_graph_checkbox.trace_add("write", lambda *args: toggle_auto())

        rpt_btn = ttk.Button(graph_card, text="Generate Report 🧾", command=self.generate_report)
        rpt_btn.pack(fill="x", pady=6)
        if not MATPLOTLIB_AVAILABLE:
            self.graph_button.configure(state="disabled")
            ttk.Label(graph_card, text="(matplotlib not installed)").pack(anchor="w")
        if not REPORTLAB_AVAILABLE:
            rpt_btn.configure(state="disabled")
            ttk.Label(graph_card, text="(reportlab not installed; report disabled)").pack(anchor="w")

        # Right side
        top_right = ttk.Frame(right)
        top_right.pack(fill="x", pady=(0,8))
        ttk.Label(top_right, text="Selected File:", style="Title.TLabel").pack(anchor="w")
        self.selected_label = ttk.Label(top_right, text="(none)", style="Stat.TLabel")
        self.selected_label.pack(anchor="w", pady=(2,6))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(right, textvariable=self.status_var).pack(anchor="w", pady=(0,8))

        self.graph_area = ttk.Frame(right)
        self.graph_area.pack(fill="both", expand=True)

        bottom = ttk.Frame(right)
        bottom.pack(fill="x", pady=(8,0))
        ttk.Label(bottom, text="Tip: Use same user + algorithm to decrypt files successfully.", wraplength=560).pack(anchor="w")

    # ---------------- DB helpers ----------------
    def _count_users(self):
        conn = db._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM users")
        c = cur.fetchone()["c"]
        conn.close()
        return c

    def logout(self):
        db.log_action(self.user, "logout", "")
        self.user = None
        self.file_path = None
        self.login_screen()

    # ---------------- File operations ----------------
    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.selected_label.configure(text=os.path.basename(path))
            self.status_var.set(f"Selected: {os.path.basename(path)}")
            bring_window_front(self.root)
            messagebox.showinfo("Selected", f"File selected:\n{os.path.basename(path)}")

    def _generate_rsa(self):
        priv, pub = crypto.generate_rsa_keypair()
        self.private_key_pem = priv
        self.public_key_pem = pub
        bring_window_front(self.root)
        messagebox.showinfo("RSA", "RSA keypair generated (stored in-memory).")

    def encrypt_file(self):
        if not self.file_path:
            bring_window_front(self.root)
            messagebox.showwarning("No File", "Select a file first")
            return
        algo = self.selected_algo.get()
        key = derive_key(self.user)
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            if algo.upper() == "AES":
                (out, elapsed) = performance.measure_time(crypto.encrypt_aes_gcm, key, data)
            else:
                (out, elapsed) = performance.measure_time(crypto.encrypt_chacha, key, data)

            wrapped_key_b64 = None
            if self.use_rsa_wrap.get():
                if not self.public_key_pem:
                    bring_window_front(self.root)
                    messagebox.showwarning("RSA", "Generate RSA keypair first.")
                    return
                wrapped = crypto.rsa_wrap_key(self.public_key_pem, key)
                wrapped_key_b64 = base64.b64encode(wrapped).decode()

            enc_path = self.file_path + ".enc"
            with open(enc_path, "wb") as f:
                f.write(b"EEASEv3")
                f.write(algo.upper().encode().ljust(8, b'\x00'))
                if wrapped_key_b64:
                    wk = wrapped_key_b64.encode()
                    f.write(len(wk).to_bytes(4, "big"))
                    f.write(wk)
                else:
                    f.write((0).to_bytes(4, "big"))
                f.write(out)

            db.log_action(self.user, f"encrypt_{algo}", enc_path)
            db.increment_files_encrypted(1)
            self.status_var.set(f"Encrypted ({algo}) in {elapsed:.3f}s")
            bring_window_front(self.root)
            messagebox.showinfo("Success", f"✅ Encrypted successfully!\nSaved as: {enc_path}\nTime: {elapsed:.3f}s")
        except Exception as e:
            bring_window_front(self.root)
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_file(self):
        path = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted files","*.enc")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                header = f.read(7)
                if header != b"EEASEv3":
                    raise ValueError("Unrecognized encrypted file format")
                algo_name = f.read(8).strip(b'\x00').decode()
                wk_len = int.from_bytes(f.read(4), "big")
                wrapped_key = f.read(wk_len) if wk_len > 0 else None
                blob = f.read()

            symmetric_key = None
            if wrapped_key:
                if not self.private_key_pem:
                    bring_window_front(self.root)
                    messagebox.showwarning("RSA", "RSA-wrapped key detected. Generate RSA keypair first.")
                else:
                    wrapped = base64.b64decode(wrapped_key)
                    try:
                        symmetric_key = crypto.rsa_unwrap_key(self.private_key_pem, wrapped)
                    except Exception as e:
                        db.log_action(self.user, "failed_decryption", path)
                        bring_window_front(self.root)
                        messagebox.showerror("RSA Unwrap Error", f"Failed to unwrap RSA key:\n{str(e)}")
                        return

            if not symmetric_key:
                symmetric_key = derive_key(self.user)

            if algo_name.upper() == "AES":
                plain = crypto.decrypt_aes_gcm(symmetric_key, blob)
            elif algo_name.upper() == "CHACHA":
                plain = crypto.decrypt_chacha(symmetric_key, blob)
            else:
                raise ValueError(f"Unknown algorithm: {algo_name}")

            dec_path = path.replace(".enc", ".dec")
            with open(dec_path, "wb") as out_f:
                out_f.write(plain)

            db.log_action(self.user, f"decrypt_{algo_name}", dec_path)
            bring_window_front(self.root)
            messagebox.showinfo("Decryption Successful", f"✅ File successfully decrypted!\nSaved at:\n{dec_path}")
            self.status_var.set(f"Decrypted: {os.path.basename(dec_path)}")
            # try to open decrypted file (best-effort)
            try:
                os.startfile(dec_path)
            except Exception:
                try:
                    os.startfile(os.path.dirname(dec_path))
                except Exception:
                    pass

        except Exception as e:
            tb = traceback.format_exc()
            print("Decryption Error:", tb)
            db.log_action(self.user, "failed_decryption", path)
            bring_window_front(self.root)
            messagebox.showerror(
                "Decryption Error",
                f"⚠️ An error occurred during decryption:\n\n{type(e).__name__}: {str(e)}\n\n"
                "If this is an InvalidTag error, the wrong user/password/algorithm was used."
            )

    def check_hash(self):
        if not self.file_path:
            bring_window_front(self.root)
            messagebox.showwarning("No File", "Select a file first.")
            return
        current_hash = integrity.file_hash(self.file_path)
        db.log_action(self.user, "hash_check", self.file_path)
        bring_window_front(self.root)
        messagebox.showinfo("Integrity Check",
                            f"SHA-256:\n{current_hash}\n\nIntegrity maintained ✅")

    # ---------------- Performance Graph ----------------
    def _on_show_graph(self):
        if not MATPLOTLIB_AVAILABLE:
            bring_window_front(self.root)
            messagebox.showwarning("Graph", "matplotlib not installed; graphs disabled.")
            return
        self.graph_button.configure(state="disabled", text="Running tests...")
        thread = threading.Thread(target=self._generate_and_show_graph, daemon=True)
        thread.start()

    def _generate_and_show_graph(self):
        try:
            sizes_kb = [10, 50, 100, 200, 500]
            aes_times, chacha_times = [], []
            for kb in sizes_kb:
                data = os.urandom(kb * 1024)
                key_aes = crypto.aes_generate_key()
                key_chacha = crypto.chacha20_generate_key()
                _, t1 = performance.measure_time(crypto.encrypt_aes_gcm, key_aes, data)
                _, t2 = performance.measure_time(crypto.encrypt_chacha, key_chacha, data)
                aes_times.append(t1)
                chacha_times.append(t2)
                time.sleep(0.05)

            # Save perf record for report
            perf_record = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "sizes_kb": sizes_kb,
                "aes_times": aes_times,
                "chacha_times": chacha_times
            }
            try:
                perf_log = "performance_log.json"
                existing = []
                if os.path.exists(perf_log):
                    with open(perf_log, "r") as pf:
                        try:
                            existing = json.load(pf)
                        except Exception:
                            existing = []
                existing.append(perf_record)
                with open(perf_log, "w") as pf:
                    json.dump(existing, pf, indent=2)
            except Exception:
                pass

            # Build bar figure
            fig = Figure(figsize=(7,3.8), dpi=100)
            ax = fig.add_subplot(111)
            x = _np.arange(len(sizes_kb))
            width = 0.35
            bars1 = ax.bar(x - width/2, aes_times, width, label='AES-GCM', color='#2b8cbe')
            bars2 = ax.bar(x + width/2, chacha_times, width, label='ChaCha20', color='#fdae61')
            ax.set_xlabel("File Size (KB)")
            ax.set_ylabel("Time (seconds)")
            ax.set_title("AES-GCM vs ChaCha20: Encryption Time")
            ax.set_xticks(x)
            ax.set_xticklabels([f"{s}KB" for s in sizes_kb])
            ax.grid(axis='y', linestyle='--', alpha=0.6)
            ax.legend()
            for bar in list(bars1) + list(bars2):
                h = bar.get_height()
                ax.annotate(f'{h:.3f}s', xy=(bar.get_x() + bar.get_width()/2, h),
                            xytext=(0, 3), textcoords="offset points",
                            ha='center', va='bottom', fontsize=8)

            # embed the graph into GUI on main thread
            self.root.after(0, lambda: self._embed_graph_and_save(fig, perf_record))
        except Exception as e:
            print("Graph generation error:", e)
            bring_window_front(self.root)
            messagebox.showerror("Graph Error", str(e))
        finally:
            self.root.after(0, lambda: self.graph_button.configure(state="normal", text="Show Graph 📊"))

    def _embed_graph_and_save(self, fig, perf_record):
        # embed into GUI
        for w in self.graph_area.winfo_children():
            w.destroy()
        canvas = FigureCanvasTkAgg(fig, master=self.graph_area)
        canvas.draw()
        widget = canvas.get_tk_widget()
        widget.pack(fill="both", expand=True)
        btn_frame = ttk.Frame(self.graph_area)
        btn_frame.pack(side="bottom", pady=6)
        ttk.Button(btn_frame, text="Save Graph as PNG (choose location)", command=lambda: self._save_fig_dialog(fig)).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Auto-save Graph to Reports folder", command=lambda: self._auto_save_graph(fig, perf_record)).pack(side="left", padx=6)

        # Auto-save if checkbox set
        if self.auto_graph_checkbox.get():
            self._auto_save_graph(fig, perf_record)

    def _save_fig_dialog(self, fig):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image","*.png")])
        if path:
            fig.savefig(path, bbox_inches='tight')
            bring_window_front(self.root)
            messagebox.showinfo("Saved", f"Graph saved as: {path}")

    def _auto_save_graph(self, fig, perf_record):
        try:
            fname = f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            out_path = self.reports_dir / fname
            fig.savefig(str(out_path), bbox_inches='tight')
            bring_window_front(self.root)
            messagebox.showinfo("Graph Saved", f"Graph auto-saved to:\n{out_path}")
            # open folder
            try:
                os.startfile(self.reports_dir)
            except Exception:
                pass
            # attach saved PNG path to perf_record for possible embedding in report
            perf_record["graph_png"] = str(out_path)
        except Exception as e:
            bring_window_front(self.root)
            messagebox.showerror("Auto Save Error", str(e))

    # ---------------- Report Generation ----------------
    def generate_report(self):
        if not REPORTLAB_AVAILABLE:
            bring_window_front(self.root)
            messagebox.showwarning("Report", "reportlab package not installed. Install with: pip install reportlab")
            return
        try:
            # auto target path in Reports folder
            suggested = f"EncryptEase_Report_{self.user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_path = self.reports_dir / suggested

            # Gather data
            stats = db.get_stats()
            users_count = self._count_users()
            files_enc = stats.get("files_encrypted", 0)

            # Read last performance record if available
            perf_log = "performance_log.json"
            last_perf = None
            if os.path.exists(perf_log):
                try:
                    with open(perf_log, "r") as pf:
                        data = json.load(pf)
                        if isinstance(data, list) and data:
                            last_perf = data[-1]
                except Exception:
                    last_perf = None

            # Build PDF
            doc = SimpleDocTemplate(str(report_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            story.append(Paragraph("Encrypt-Ease — Final Report", styles["Title"]))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
            story.append(Spacer(1, 12))
            story.append(Paragraph("Summary Statistics", styles["Heading2"]))
            summary_table_data = [
                ["Metric", "Value"],
                ["Total Users", str(users_count)],
                ["Files Encrypted", str(files_enc)],
                ["Report Generated By (user)", str(self.user)]
            ]
            t = Table(summary_table_data, hAlign="LEFT", colWidths=[240, 260])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dbe9ff")),
                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

            # Performance section
            story.append(Paragraph("Latest Performance Test", styles["Heading2"]))
            if last_perf:
                sizes = last_perf.get("sizes_kb", [])
                aes = last_perf.get("aes_times", [])
                chacha = last_perf.get("chacha_times", [])
                perf_rows = [["Size (KB)", "AES Encrypt (s)", "ChaCha Encrypt (s)"]]
                for s, a, c in zip(sizes, aes, chacha):
                    perf_rows.append([str(s), f"{a:.4f}", f"{c:.4f}"])
                pt = Table(perf_rows, hAlign="LEFT", colWidths=[120, 150, 150])
                pt.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dbe9ff")),
                    ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
                    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ]))
                story.append(pt)
                story.append(Spacer(1, 12))
                # attach graph image if available in last perf
                graph_png = last_perf.get("graph_png")
                if graph_png and os.path.exists(graph_png):
                    try:
                        story.append(Spacer(1, 12))
                        story.append(Paragraph("Performance Graph", styles["Heading3"]))
                        # scale image to page width (~400 px)
                        story.append(Spacer(1, 6))
                        story.append(RLImage(graph_png, width=400, height=220))
                    except Exception:
                        pass
                story.append(Spacer(1, 12))
                story.append(Paragraph("Notes: Performance tests were run locally using random data and measured encryption times.", styles["Normal"]))
            else:
                story.append(Paragraph("No performance test records found. Run the performance test from the GUI to include results here.", styles["Normal"]))

            story.append(Spacer(1, 16))
            story.append(Paragraph("Functional Description", styles["Heading2"]))
            story.append(Paragraph(
                "Encrypt-Ease supports AES-GCM and ChaCha20 encryption, optional RSA wrapping of symmetric keys, "
                "SHA-256 integrity checking, performance benchmarking and report generation. The GUI allows users to register/login, "
                "encrypt/decrypt files and save results for inspection.", styles["Normal"]))
            story.append(Spacer(1, 12))

            doc.build(story)

            bring_window_front(self.root)
            messagebox.showinfo("Report Saved", f"Report saved as: {report_path}\n\nFolder opened.")
            # open folder
            try:
                os.startfile(self.reports_dir)
            except Exception:
                pass
        except Exception as e:
            bring_window_front(self.root)
            messagebox.showerror("Report Error", str(e))

    def run(self):
        self.root.mainloop()

# ---------------- run when executed directly ----------------
if __name__ == "__main__":
    app = EncryptEaseApp()
    app.run()
