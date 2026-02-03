"""
Main GUI application for Secure File Vault
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
import datetime
import json

# Import from our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.symmetric import generate_key, save_key, load_key
from crypto.pki import generate_rsa_keypair
from crypto.vault_ops import encrypt_produce_files, decrypt_using_files, verify_signature_standalone
from utils.helpers import open_path

# Military theme colors
BG_COLOR = "#000000"
FG_COLOR = "#00ff00"
ACCENT_COLOR = "#ff6600"
SECONDARY_COLOR = "#0a0a0a"
HIGHLIGHT_COLOR = "#1a1a1a"
ERROR_COLOR = "#ff0000"
WARNING_COLOR = "#ffff00"
SUCCESS_COLOR = "#00ff00"
REGISTER_COLOR = "#0066cc"

DEFAULT_OUT_DIR = os.path.join(os.getcwd(), "secure_vault")
os.makedirs(DEFAULT_OUT_DIR, exist_ok=True)

class MainApplication:
    """Main application window with military-themed UI"""
    
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.root = tk.Tk()
        self.setup_window()
        self.configure_styles()
        self.build_ui()
        self.root.mainloop()
        
    def setup_window(self):
        """Configure main window properties"""
        self.root.title("SECURE FILE VAULT")
        self.root.geometry("1024x768")
        self.root.minsize(1024, 768)
        self.root.configure(bg=BG_COLOR)
        
        self.last_restored = ""
        self.current_key = None
        
    def configure_styles(self):
        """Configure ttk styles for military theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TNotebook', background=BG_COLOR, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=SECONDARY_COLOR,
                       foreground=FG_COLOR,
                       padding=[20, 10],
                       font=('Courier', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', HIGHLIGHT_COLOR)],
                 foreground=[('selected', ACCENT_COLOR)])
        
        style.configure('Military.TLabel',
                       background=BG_COLOR,
                       foreground=FG_COLOR,
                       font=('Courier', 9))
        
        style.configure('Military.TButton',
                       background=SECONDARY_COLOR,
                       foreground=FG_COLOR,
                       borderwidth=2,
                       relief='raised',
                       font=('Courier', 9, 'bold'))
        style.map('Military.TButton',
                 background=[('active', HIGHLIGHT_COLOR),
                           ('pressed', ACCENT_COLOR)],
                 foreground=[('active', FG_COLOR),
                           ('pressed', BG_COLOR)])
        
        style.configure('Military.TEntry',
                       fieldbackground=HIGHLIGHT_COLOR,
                       foreground=ACCENT_COLOR,
                       insertcolor=ACCENT_COLOR,
                       borderwidth=2,
                       relief='sunken')
        
        style.configure('Military.TFrame',
                       background=BG_COLOR)

    def _entry_with_button(self, parent, row, label, btn_text, cmd, width=80):
        """Helper to create entry with browse button"""
        if label:
            lbl = ttk.Label(parent, text=label, style='Military.TLabel')
            lbl.grid(row=row, column=0, sticky="w", pady=(10, 5))
            row += 1
        frame = ttk.Frame(parent, style='Military.TFrame')
        frame.grid(row=row, column=0, sticky="ew", pady=5)
        frame.columnconfigure(0, weight=1)
        
        entry = ttk.Entry(frame, width=width, style='Military.TEntry')
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        btn = ttk.Button(frame, text=btn_text, command=cmd, style='Military.TButton')
        btn.grid(row=0, column=1)
        return entry, row + 1

    def build_ui(self):
        """Build the main application UI"""
        main_frame = ttk.Frame(self.root, style='Military.TFrame')
        main_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Header
        header_frame = tk.Frame(main_frame, bg=BG_COLOR, relief="ridge", bd=3)
        header_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(header_frame, text="▓"*120, bg=BG_COLOR, fg=ACCENT_COLOR,
                font=("Courier", 1)).pack()
        
        title_font = font.Font(family="Courier", size=16, weight="bold")
        tk.Label(header_frame, 
                text="▓▓▓ SECURE FILE VAULT v2.0 ▓▓▓ MILITARY-GRADE ENCRYPTION ▓▓▓",
                bg=BG_COLOR, fg=ACCENT_COLOR, font=title_font).pack(pady=5)
        
        user_info = tk.Label(header_frame, 
                           text=f"USER: {self.user_manager.current_user} | AES-256-GCM | RSA-4096",
                           bg=BG_COLOR, fg=FG_COLOR, font=("Courier", 9))
        user_info.pack(pady=(0, 5))
        
        tk.Label(header_frame, text="▓"*120, bg=BG_COLOR, fg=ACCENT_COLOR,
                font=("Courier", 1)).pack()
        
        # Status bar
        self.status_bar = tk.Label(main_frame, text="[SYSTEM] Secure session active...", 
                                  bg=BG_COLOR, fg=SUCCESS_COLOR, font=("Courier", 9, "bold"),
                                  relief="sunken", bd=1)
        self.status_bar.pack(side="bottom", fill="x", padx=5, pady=5)
        
        # Notebook tabs
        nb = ttk.Notebook(main_frame)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        
        enc_tab = ttk.Frame(nb, style='Military.TFrame')
        dec_tab = ttk.Frame(nb, style='Military.TFrame')
        verify_tab = ttk.Frame(nb, style='Military.TFrame')
        key_tab = ttk.Frame(nb, style='Military.TFrame')
        pki_tab = ttk.Frame(nb, style='Military.TFrame')
        
        nb.add(enc_tab, text="[ENCRYPT]")
        nb.add(dec_tab, text="[DECRYPT]")
        nb.add(verify_tab, text="[VERIFY]")
        nb.add(key_tab, text="[KEY MGMT]")
        nb.add(pki_tab, text="[PKI GEN]")
        
        for tab in [enc_tab, dec_tab, verify_tab, key_tab, pki_tab]:
            tab.columnconfigure(0, weight=1)
        
        self._build_encrypt_tab(enc_tab)
        self._build_decrypt_tab(dec_tab)
        self._build_verify_tab(verify_tab)
        self._build_key_tab(key_tab)
        self._build_pki_tab(pki_tab)
        
        # Bottom buttons
        bottom_frame = tk.Frame(main_frame, bg=BG_COLOR, relief="ridge", bd=2)
        bottom_frame.pack(fill="x", pady=(10, 0))
        
        tk.Button(bottom_frame, text="[OPEN RESTORED]", 
                 bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                 font=("Courier", 9, "bold"), relief="raised", bd=2,
                 command=self.open_restored).pack(side="left", padx=5, pady=5)
        
        tk.Button(bottom_frame, text="[OPEN VAULT]", 
                 bg=SECONDARY_COLOR, fg=FG_COLOR,
                 font=("Courier", 9, "bold"), relief="raised", bd=2,
                 command=self.open_outfolder).pack(side="left", padx=5, pady=5)
        
        tk.Button(bottom_frame, text="[WIPE KEY]", 
                 bg=SECONDARY_COLOR, fg=WARNING_COLOR,
                 font=("Courier", 9, "bold"), relief="raised", bd=2,
                 command=self.wipe_key).pack(side="left", padx=5, pady=5)
        
        tk.Button(bottom_frame, text="[LOGOUT]", 
                 bg=SECONDARY_COLOR, fg=ERROR_COLOR,
                 font=("Courier", 9, "bold"), relief="raised", bd=2,
                 command=self.logout).pack(side="right", padx=5, pady=5)
        
        tk.Button(bottom_frame, text="[EXIT SYSTEM]", 
                 bg=BG_COLOR, fg=ERROR_COLOR,
                 font=("Courier", 9, "bold"), relief="raised", bd=2,
                 command=self.root.quit).pack(side="right", padx=5, pady=5)

    def _build_encrypt_tab(self, parent):
        """Build encryption tab"""
        row = 0
        ttk.Label(parent, text="▓ ENCRYPTION MODULE ▓", 
                 style='Military.TLabel', foreground=ACCENT_COLOR,
                 font=('Courier', 12, 'bold')).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1
        
        self.enc_file_entry, row = self._entry_with_button(
            parent, row, "TARGET FILE:", "[BROWSE]", self.browse_enc_file
        )
        
        self.enc_key_entry, row = self._entry_with_button(
            parent, row, "ENCRYPTION KEY:", "[SELECT KEY]", self.browse_enc_key
        )
        
        self.enc_out_entry, row = self._entry_with_button(
            parent, row, "OUTPUT VAULT:", "[CHOOSE]", self.choose_enc_out
        )
        self.enc_out_entry.insert(0, DEFAULT_OUT_DIR)
        
        ttk.Separator(parent, orient="horizontal").grid(
            row=row, column=0, sticky="ew", pady=20
        )
        row += 1
        
        self.enc_privkey_entry, row = self._entry_with_button(
            parent, row, "RSA PRIVATE KEY:", "[BROWSE]", self.browse_enc_privkey
        )
        
        execute_btn = tk.Button(parent, text="[EXECUTE ENCRYPTION]", 
                               bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                               font=('Courier', 10, 'bold'), relief="raised", bd=3,
                               command=self.do_encrypt)
        execute_btn.grid(row=row, column=0, sticky="w", pady=20)
        row += 1
        
        hash_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        hash_frame.grid(row=row, column=0, sticky="ew", pady=10)
        hash_frame.columnconfigure(0, weight=1)
        
        tk.Label(hash_frame, text="FILE HASH:", 
                bg=BG_COLOR, fg=FG_COLOR, font=('Courier', 9, 'bold')).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.enc_hash_display = tk.Text(hash_frame, height=2, width=80,
                                       bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                       font=('Courier', 8),
                                       borderwidth=1, relief='flat')
        self.enc_hash_display.grid(row=1, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.enc_hash_display.insert("1.0", "[NO HASH]")
        self.enc_hash_display.config(state="disabled")

    def _build_decrypt_tab(self, parent):
        """Build decryption tab"""
        row = 0
        ttk.Label(parent, text="▓ DECRYPTION MODULE ▓", 
                 style='Military.TLabel', foreground=ACCENT_COLOR,
                 font=('Courier', 12, 'bold')).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1
        
        self.dec_vault_entry, row = self._entry_with_button(
            parent, row, ".VAULT FILE:", "[BROWSE]", self.browse_vault
        )
        
        self.dec_key_entry, row = self._entry_with_button(
            parent, row, "DECRYPTION KEY:", "[SELECT KEY]", self.browse_dec_key
        )
        
        self.dec_pubkey_entry, row = self._entry_with_button(
            parent, row, "RSA PUBLIC KEY:", "[BROWSE]", self.browse_dec_pubkey
        )
        
        self.dec_out_entry, row = self._entry_with_button(
            parent, row, "RESTORE LOCATION:", "[CHOOSE]", self.choose_dec_out
        )
        self.dec_out_entry.insert(0, DEFAULT_OUT_DIR)
        
        execute_btn = tk.Button(parent, text="[EXECUTE DECRYPTION]", 
                               bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                               font=('Courier', 10, 'bold'), relief="raised", bd=3,
                               command=self.do_decrypt)
        execute_btn.grid(row=row, column=0, sticky="w", pady=20)
        row += 1
        
        hash_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        hash_frame.grid(row=row, column=0, sticky="ew", pady=10)
        hash_frame.columnconfigure(0, weight=1)
        
        tk.Label(hash_frame, text="VERIFIED HASH:", 
                bg=BG_COLOR, fg=FG_COLOR, font=('Courier', 9, 'bold')).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.dec_hash_display = tk.Text(hash_frame, height=2, width=80,
                                       bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                       font=('Courier', 8),
                                       borderwidth=1, relief='flat')
        self.dec_hash_display.grid(row=1, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.dec_hash_display.insert("1.0", "[NO HASH]")
        self.dec_hash_display.config(state="disabled")

    def _build_verify_tab(self, parent):
        """Build verification tab"""
        row = 0
        ttk.Label(parent, text="▓ SIGNATURE VERIFICATION ▓", 
                 style='Military.TLabel', foreground=ACCENT_COLOR,
                 font=('Courier', 12, 'bold')).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1
        
        self.verify_hash_entry, row = self._entry_with_button(
            parent, row, ".HASH FILE:", "[BROWSE]", self.browse_verify_hash
        )
        
        self.verify_sig_entry, row = self._entry_with_button(
            parent, row, ".SIG FILE:", "[BROWSE]", self.browse_verify_sig
        )
        
        self.verify_pubkey_entry, row = self._entry_with_button(
            parent, row, "RSA PUBLIC KEY:", "[BROWSE]", self.browse_verify_pubkey
        )
        
        verify_btn = tk.Button(parent, text="[VERIFY SIGNATURE]", 
                              bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                              font=('Courier', 10, 'bold'), relief="raised", bd=3,
                              command=self.do_verify_signature)
        verify_btn.grid(row=row, column=0, sticky="w", pady=20)
        row += 1
        
        result_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        result_frame.grid(row=row, column=0, sticky="ew", pady=20)
        result_frame.columnconfigure(0, weight=1)
        
        self.verify_result = tk.Text(result_frame, height=3, width=80,
                                    bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                    font=('Courier', 9, 'bold'),
                                    borderwidth=1, relief='flat')
        self.verify_result.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.verify_result.insert("1.0", "[AWAITING VERIFICATION]")
        self.verify_result.config(state="disabled")

    def _build_key_tab(self, parent):
        """Build key management tab"""
        row = 0
        ttk.Label(parent, text="▓ KEY MANAGEMENT ▓", 
                 style='Military.TLabel', foreground=ACCENT_COLOR,
                 font=('Courier', 12, 'bold')).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1
        
        status_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        status_frame.grid(row=row, column=0, sticky="ew", pady=10)
        
        self.key_status = tk.Text(status_frame, height=2, width=80,
                                 bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                 font=('Courier', 9),
                                 borderwidth=1, relief='flat')
        self.key_status.pack(fill="x", padx=5, pady=5)
        self.key_status.insert("1.0", "[NO KEY LOADED IN MEMORY]")
        self.key_status.config(state="disabled")
        row += 1
        
        btn_frame = tk.Frame(parent, bg=BG_COLOR)
        btn_frame.grid(row=row, column=0, sticky="w", pady=10)
        
        tk.Button(btn_frame, text="[GENERATE KEY]", 
                 bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                 font=('Courier', 9, 'bold'), relief="raised", bd=2,
                 command=self.generate_key_file).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="[LOAD KEY]", 
                 bg=SECONDARY_COLOR, fg=FG_COLOR,
                 font=('Courier', 9, 'bold'), relief="raised", bd=2,
                 command=self.load_key_file).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="[VIEW KEY]", 
                 bg=SECONDARY_COLOR, fg=WARNING_COLOR,
                 font=('Courier', 9, 'bold'), relief="raised", bd=2,
                 command=self.view_key).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="[EXPORT KEY]", 
                 bg=SECONDARY_COLOR, fg=FG_COLOR,
                 font=('Courier', 9, 'bold'), relief="raised", bd=2,
                 command=self.export_key).pack(side="left", padx=5)
        
        key_display_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        key_display_frame.grid(row=row+1, column=0, sticky="ew", pady=10)
        key_display_frame.columnconfigure(0, weight=1)
        
        self.key_display = tk.Text(key_display_frame, height=4, width=80,
                                  bg=HIGHLIGHT_COLOR, fg=WARNING_COLOR,
                                  font=('Courier', 8),
                                  borderwidth=1, relief='flat')
        self.key_display.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.key_display.insert("1.0", "[KEY AREA SECURED]")
        self.key_display.config(state="disabled")

    def _build_pki_tab(self, parent):
        """Build PKI generation tab"""
        row = 0
        ttk.Label(parent, text="▓ PKI GENERATION ▓", 
                 style='Military.TLabel', foreground=ACCENT_COLOR,
                 font=('Courier', 12, 'bold')).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1
        
        size_frame = tk.Frame(parent, bg=BG_COLOR)
        size_frame.grid(row=row, column=0, sticky="w", pady=10)
        
        tk.Label(size_frame, text="KEY STRENGTH:", 
                bg=BG_COLOR, fg=FG_COLOR, font=('Courier', 9, 'bold')).pack(side="left", padx=(0, 10))
        
        self.keysize_var = tk.IntVar(value=4096)
        size_combo = ttk.Combobox(size_frame, 
                                 textvariable=self.keysize_var,
                                 values=[2048, 3072, 4096, 8192],
                                 width=8,
                                 state="readonly")
        size_combo.pack(side="left")
        row += 1
        
        tk.Button(parent, text="[GENERATE RSA KEYPAIR]", 
                 bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                 font=('Courier', 10, 'bold'), relief="raised", bd=3,
                 command=self.generate_pki_keys).grid(row=row, column=0, sticky="w", pady=10)
        row += 1
        
        info_frame = tk.Frame(parent, bg=BG_COLOR, relief="sunken", bd=2)
        info_frame.grid(row=row, column=0, sticky="ew", pady=20)
        
        info_text = tk.Text(info_frame, height=6, width=80,
                           bg=HIGHLIGHT_COLOR, fg=FG_COLOR,
                           font=('Courier', 8),
                           borderwidth=1, relief='flat')
        info_text.pack(fill="x", padx=5, pady=5)
        info_text.insert("1.0", 
            "[PKI SYSTEM ACTIVE]\n"
            "• Private key: Used for signing during encryption\n"
            "• Public key: Used for verification during decryption\n"
            "• 4096-bit RSA recommended for maximum security\n"
            "• Never share private keys - store in secure location\n"
            "• Signature verification is MANDATORY for all operations"
        )
        info_text.config(state="disabled")

    # ---------- File dialogs ----------
    def browse_enc_file(self):
        f = filedialog.askopenfilename(title="Select file to encrypt")
        if f:
            self.enc_file_entry.delete(0, tk.END)
            self.enc_file_entry.insert(0, f)

    def browse_enc_key(self):
        f = filedialog.askopenfilename(
            title="Select encryption key file",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
        )
        if f:
            self.enc_key_entry.delete(0, tk.END)
            self.enc_key_entry.insert(0, f)

    def browse_enc_privkey(self):
        f = filedialog.askopenfilename(
            title="Select RSA private key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if f:
            self.enc_privkey_entry.delete(0, tk.END)
            self.enc_privkey_entry.insert(0, f)

    def choose_enc_out(self):
        d = filedialog.askdirectory(title="Choose output folder")
        if d:
            self.enc_out_entry.delete(0, tk.END)
            self.enc_out_entry.insert(0, d)

    def browse_vault(self):
        f = filedialog.askopenfilename(
            title="Select .vault file",
            filetypes=[("Vault", "*.vault"), ("All files", "*.*")],
        )
        if not f:
            return
        self.dec_vault_entry.delete(0, tk.END)
        self.dec_vault_entry.insert(0, f)

    def browse_dec_key(self):
        f = filedialog.askopenfilename(
            title="Select decryption key file",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
        )
        if f:
            self.dec_key_entry.delete(0, tk.END)
            self.dec_key_entry.insert(0, f)

    def browse_dec_pubkey(self):
        f = filedialog.askopenfilename(
            title="Select RSA public key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if f:
            self.dec_pubkey_entry.delete(0, tk.END)
            self.dec_pubkey_entry.insert(0, f)

    def choose_dec_out(self):
        d = filedialog.askdirectory(title="Choose restore folder")
        if d:
            self.dec_out_entry.delete(0, tk.END)
            self.dec_out_entry.insert(0, d)

    def browse_verify_hash(self):
        f = filedialog.askopenfilename(
            title="Select .hash file",
            filetypes=[("Hash", "*.hash"), ("All files", "*.*")],
        )
        if f:
            self.verify_hash_entry.delete(0, tk.END)
            self.verify_hash_entry.insert(0, f)

    def browse_verify_sig(self):
        f = filedialog.askopenfilename(
            title="Select signature file",
            filetypes=[("Signature", "*.sig"), ("All files", "*.*")],
        )
        if f:
            self.verify_sig_entry.delete(0, tk.END)
            self.verify_sig_entry.insert(0, f)

    def browse_verify_pubkey(self):
        f = filedialog.askopenfilename(
            title="Select RSA public key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if f:
            self.verify_pubkey_entry.delete(0, tk.END)
            self.verify_pubkey_entry.insert(0, f)

    # ---------- Key Management ----------
    def generate_key_file(self):
        key = generate_key()
        key_hex = key.hex()
        
        self.key_display.config(state="normal")
        self.key_display.delete("1.0", tk.END)
        self.key_display.insert("1.0", f"[GENERATED KEY - KEEP SECURE]\n{key_hex[:64]}...")
        self.key_display.config(state="disabled")
        
        f = filedialog.asksaveasfilename(
            title="Save encryption key",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            initialfile=f"key_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.key"
        )
        if f:
            save_key(key, f)
            self.current_key = key
            self.key_status.config(state="normal")
            self.key_status.delete("1.0", tk.END)
            self.key_status.insert("1.0", f"[KEY LOADED] {os.path.basename(f)}")
            self.key_status.config(state="disabled")
            self._update_status(f"[KEY] Generated and saved: {f}")
            messagebox.showinfo("Key Generated", 
                              f"256-bit encryption key generated and saved.\n\n"
                              f"File: {os.path.basename(f)}\n"
                              f"Location: {f}\n\n"
                              "KEEP THIS FILE SECURE - IT CANNOT BE RECOVERED IF LOST!")

    def load_key_file(self):
        f = filedialog.askopenfilename(
            title="Load encryption key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
        )
        if f:
            try:
                key = load_key(f)
                self.current_key = key
                self.key_status.config(state="normal")
                self.key_status.delete("1.0", tk.END)
                self.key_status.insert("1.0", f"[KEY LOADED] {os.path.basename(f)}")
                self.key_status.config(state="disabled")
                self._update_status(f"[KEY] Loaded: {os.path.basename(f)}")
            except Exception as e:
                self._update_status(f"[ERROR] Failed to load key: {str(e)}", error=True)

    def view_key(self):
        if self.current_key:
            key_hex = self.current_key.hex()
            self.key_display.config(state="normal")
            self.key_display.delete("1.0", tk.END)
            self.key_display.insert("1.0", f"[ACTIVE ENCRYPTION KEY]\n{key_hex}")
            self.key_display.config(state="disabled")
        else:
            self._update_status("[ERROR] No key loaded", error=True)

    def export_key(self):
        if not self.current_key:
            self._update_status("[ERROR] No key to export", error=True)
            return
        
        f = filedialog.asksaveasfilename(
            title="Export encryption key",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            initialfile=f"exported_key_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.key"
        )
        if f:
            save_key(self.current_key, f)
            self._update_status(f"[KEY] Exported to: {f}")

    def wipe_key(self):
        if self.current_key:
            self.current_key = None
            self.key_status.config(state="normal")
            self.key_status.delete("1.0", tk.END)
            self.key_status.insert("1.0", "[KEY WIPED FROM MEMORY]")
            self.key_status.config(state="disabled")
            self.key_display.config(state="normal")
            self.key_display.delete("1.0", tk.END)
            self.key_display.insert("1.0", "[KEY AREA SECURED]")
            self.key_display.config(state="disabled")
            self._update_status("[SECURITY] Key wiped from memory")

    # ---------- Actions ----------
    def do_encrypt(self):
        infile = self.enc_file_entry.get().strip()
        if not infile or not os.path.exists(infile):
            self._update_status("[ERROR] Select a valid file to encrypt", error=True)
            return
        
        key_file = self.enc_key_entry.get().strip()
        if key_file and os.path.exists(key_file):
            try:
                key = load_key(key_file)
            except Exception as e:
                self._update_status(f"[ERROR] Failed to load key file: {str(e)}", error=True)
                return
        elif self.current_key:
            key = self.current_key
        else:
            self._update_status("[ERROR] No encryption key available", error=True)
            return
        
        out_dir = self.enc_out_entry.get().strip() or DEFAULT_OUT_DIR
        rsa_priv = self.enc_privkey_entry.get().strip()
        if not rsa_priv:
            self._update_status("[ERROR] RSA private key is required", error=True)
            return

        try:
            self._update_status("[ENCRYPTION] Initializing...")
            vault_p, hash_p, meta_p, sig_p, h = encrypt_produce_files(
                infile,
                key,
                out_dir,
                rsa_priv,
                status_cb=self._set_enc_status,
                current_user=self.user_manager.current_user
            )
            
            self.enc_hash_display.config(state="normal")
            self.enc_hash_display.delete("1.0", tk.END)
            self.enc_hash_display.insert("1.0", h)
            self.enc_hash_display.config(state="disabled")

            files = [
                os.path.basename(vault_p),
                os.path.basename(hash_p),
                os.path.basename(meta_p),
                os.path.basename(sig_p),
            ]
            self._update_status(f"[SUCCESS] Encrypted: {os.path.basename(infile)}")
            messagebox.showinfo(
                "Encryption Complete",
                "Files created:\n" + "\n".join(files) + "\n\n" +
                "SHA-256: " + h + "\n\n" +
                "RSA signature applied and verified."
            )
        except Exception as e:
            self._update_status(f"[ERROR] Encryption failed: {str(e)}", error=True)

    def do_decrypt(self):
        vault = self.dec_vault_entry.get().strip()
        if not vault or not os.path.exists(vault):
            self._update_status("[ERROR] Select a valid .vault file", error=True)
            return
        
        key_file = self.dec_key_entry.get().strip()
        if key_file and os.path.exists(key_file):
            try:
                key = load_key(key_file)
            except Exception as e:
                self._update_status(f"[ERROR] Failed to load key file: {str(e)}", error=True)
                return
        elif self.current_key:
            key = self.current_key
        else:
            self._update_status("[ERROR] No decryption key available", error=True)
            return
        
        folder = os.path.dirname(vault) or "."
        base = os.path.splitext(os.path.basename(vault))[0]
        
        meta_path = os.path.join(folder, base + ".meta.json")
        
        if not os.path.exists(meta_path):
            self._update_status("[ERROR] .meta.json not found", error=True)
            return
        
        out_dir = self.dec_out_entry.get().strip() or DEFAULT_OUT_DIR
        rsa_pub = self.dec_pubkey_entry.get().strip()
        if not rsa_pub:
            self._update_status("[ERROR] RSA public key is required", error=True)
            return

        try:
            self._update_status("[DECRYPTION] Initializing...")
            restored, vhash, sig_ok = decrypt_using_files(
                vault,
                key,
                meta_path,
                out_dir,
                rsa_pub,
                status_cb=self._set_dec_status
            )
            
            self.last_restored = restored
            
            self.dec_hash_display.config(state="normal")
            self.dec_hash_display.delete("1.0", tk.END)
            self.dec_hash_display.insert("1.0", vhash)
            self.dec_hash_display.config(state="disabled")
            
            self._update_status(f"[SUCCESS] Decrypted: {os.path.basename(restored)}")
            msg = (
                f"File restored: {restored}\n\n"
                f"SHA-256 verified: {vhash}\n\n"
                "RSA signature: VERIFIED"
            )
            messagebox.showinfo("Decryption Complete", msg)
        except Exception as e:
            error_msg = str(e)
            if "signature verification" in error_msg.lower():
                self._update_status("[SECURITY] Signature verification FAILED", error=True)
                messagebox.showerror(
                    "Security Alert",
                    "Signature verification FAILED!\n\n"
                    "Decryption blocked for security.\n"
                    "File may be tampered or wrong key used."
                )
            else:
                self._update_status(f"[ERROR] Decryption failed: {error_msg}", error=True)

    def do_verify_signature(self):
        hash_path = self.verify_hash_entry.get().strip()
        sig_path = self.verify_sig_entry.get().strip()
        pub_key_path = self.verify_pubkey_entry.get().strip()

        if not all([hash_path, sig_path, pub_key_path]):
            self._update_status("[ERROR] All fields required for verification", error=True)
            return
        
        if not all([os.path.exists(p) for p in [hash_path, sig_path, pub_key_path]]):
            self._update_status("[ERROR] One or more files not found", error=True)
            return

        try:
            self._update_status("[VERIFICATION] Starting...")
            is_valid, hash_hex, error_msg = verify_signature_standalone(
                hash_path, sig_path, pub_key_path, status_cb=self._set_verify_status
            )

            if error_msg:
                self._update_status(f"[ERROR] Verification failed: {error_msg}", error=True)
                return

            self.verify_result.config(state="normal")
            self.verify_result.delete("1.0", tk.END)
            
            if is_valid:
                self._update_status("[SECURITY] Signature VERIFIED")
                self.verify_result.insert("1.0", "[✓ SIGNATURE VALID]\nFile is authentic and untampered")
                self.verify_result.config(bg=HIGHLIGHT_COLOR, fg=SUCCESS_COLOR)
            else:
                self._update_status("[SECURITY] Signature INVALID", error=True)
                self.verify_result.insert("1.0", "[✗ SIGNATURE INVALID]\nFile may be tampered or wrong key used")
                self.verify_result.config(bg=HIGHLIGHT_COLOR, fg=ERROR_COLOR)
            
            self.verify_result.config(state="disabled")
        except Exception as e:
            self._update_status(f"[ERROR] Verification failed: {str(e)}", error=True)

    # ---------- Status updates ----------
    def _update_status(self, message, error=False):
        color = ERROR_COLOR if error else SUCCESS_COLOR
        self.status_bar.config(text=message, foreground=color)
        self.root.update_idletasks()

    def _set_enc_status(self, txt):
        self._update_status(f"[ENCRYPTION] {txt}")

    def _set_dec_status(self, txt):
        self._update_status(f"[DECRYPTION] {txt}")

    def _set_verify_status(self, txt):
        self._update_status(f"[VERIFICATION] {txt}")

    # ---------- Misc functions ----------
    def generate_pki_keys(self):
        d = filedialog.askdirectory(
            title="Choose folder for RSA keypair"
        )
        if not d:
            return
        bits = int(self.keysize_var.get())
        try:
            priv_p, pub_p = generate_rsa_keypair(d, bits=bits)
            self._update_status(f"[PKI] Generated {bits}-bit RSA keypair")
            messagebox.showinfo(
                "PKI Keys Generated",
                f"Generated {bits}-bit RSA keypair:\n\n"
                f"Private: {os.path.basename(priv_p)}\n"
                f"Public:  {os.path.basename(pub_p)}\n\n"
                f"Location: {d}\n\n"
                "KEEP PRIVATE KEY SECURE!"
            )
        except Exception as e:
            self._update_status(f"[ERROR] Key generation failed: {str(e)}", error=True)

    def open_restored(self):
        if self.last_restored and os.path.exists(self.last_restored):
            open_path(self.last_restored)
        else:
            self._update_status("[ERROR] No restored file found", error=True)

    def open_outfolder(self):
        folder = DEFAULT_OUT_DIR
        if os.path.exists(folder):
            open_path(folder)
        else:
            self._update_status(f"[ERROR] Folder not found: {folder}", error=True)
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.current_key = None
            self.user_manager.current_user = None
            self.root.destroy()
            from auth.auth_window import AuthWindow
            AuthWindow()