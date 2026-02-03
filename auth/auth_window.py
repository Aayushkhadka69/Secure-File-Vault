"""
Authentication window for user login and registration
"""

import tkinter as tk
from tkinter import font
from auth.user_manager import UserManager
from gui.main_app import MainApplication

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

class AuthWindow:
    """Login and registration window with military-themed UI"""
    
    def __init__(self):
        self.user_manager = UserManager()
        self.root = tk.Tk()
        self.setup_window()
        self.build_ui()
        self.root.mainloop()
        
    def setup_window(self):
        """Configure window properties"""
        self.root.title("SECURE FILE VAULT - ACCESS CONTROL")
        self.root.geometry("600x500")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(True, True)
        
        # Force window to top initially
        self.root.attributes('-topmost', True)
        self.root.focus_force()
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        
        self.center_window()
        
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'600x500+{x}+{y}')
        
    def build_ui(self):
        """Build the authentication UI"""
        main_frame = tk.Frame(self.root, bg=BG_COLOR)
        main_frame.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Title section
        title_font = font.Font(family="Courier", size=18, weight="bold")
        tk.Label(main_frame, text="╔══════════════════════════════════════╗", 
                bg=BG_COLOR, fg=ACCENT_COLOR, font=("Courier", 10)).pack()
        tk.Label(main_frame, text="║       SECURE FILE VAULT v2.0         ║", 
                bg=BG_COLOR, fg=ACCENT_COLOR, font=title_font).pack()
        tk.Label(main_frame, text="║      MILITARY-GRADE SECURITY         ║", 
                bg=BG_COLOR, fg=ERROR_COLOR, font=("Courier", 10, "bold")).pack()
        tk.Label(main_frame, text="╚══════════════════════════════════════╝", 
                bg=BG_COLOR, fg=ACCENT_COLOR, font=("Courier", 10)).pack(pady=(0, 30))
        
        # Instructions
        tk.Label(main_frame, 
                text="NEW USER? Click REGISTER button below\nEXISTING USER? Enter credentials and click LOGIN",
                bg=BG_COLOR, fg=WARNING_COLOR, 
                font=("Courier", 9)).pack(pady=(0, 20))
        
        # Login form
        login_frame = tk.Frame(main_frame, bg=SECONDARY_COLOR, relief="ridge", bd=2)
        login_frame.pack(pady=20, ipadx=20, ipady=20)
        
        # Username field
        tk.Label(login_frame, text="USERNAME:", 
                bg=SECONDARY_COLOR, fg=FG_COLOR, 
                font=("Courier", 11, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.username_entry = tk.Entry(login_frame, bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                      insertbackground=ACCENT_COLOR, font=("Courier", 11),
                                      width=30, relief="sunken", bd=2)
        self.username_entry.grid(row=1, column=0, pady=(0, 15), padx=10)
        self.username_entry.focus()
        
        # Password field
        tk.Label(login_frame, text="PASSWORD:", 
                bg=SECONDARY_COLOR, fg=FG_COLOR, 
                font=("Courier", 11, "bold")).grid(row=2, column=0, sticky="w", pady=(0, 5))
        self.password_entry = tk.Entry(login_frame, bg=HIGHLIGHT_COLOR, fg=ACCENT_COLOR,
                                      insertbackground=ACCENT_COLOR, font=("Courier", 11),
                                      width=30, relief="sunken", bd=2, show="•")
        self.password_entry.grid(row=3, column=0, pady=(0, 20), padx=10)
        
        # Requirements
        tk.Label(login_frame, 
                text="Username: min 4 chars | Password: min 8 chars",
                bg=SECONDARY_COLOR, fg=WARNING_COLOR,
                font=("Courier", 8)).grid(row=4, column=0, pady=(0, 10))
        
        # Status label
        self.status_label = tk.Label(login_frame, text="Enter credentials or register new user", 
                                     bg=SECONDARY_COLOR, fg=FG_COLOR,
                                     font=("Courier", 9))
        self.status_label.grid(row=5, column=0, pady=(0, 15))
        
        # Buttons
        btn_frame = tk.Frame(login_frame, bg=SECONDARY_COLOR)
        btn_frame.grid(row=6, column=0, pady=(0, 10))
        
        self.login_btn = tk.Button(btn_frame, text="LOGIN", bg=SECONDARY_COLOR, fg=ACCENT_COLOR,
                                  font=("Courier", 10, "bold"), relief="raised", bd=3,
                                  width=12, height=2, command=self.login)
        self.login_btn.pack(side="left", padx=5)
        
        self.register_btn = tk.Button(btn_frame, text="REGISTER", bg=SECONDARY_COLOR, fg=REGISTER_COLOR,
                                     font=("Courier", 10, "bold"), relief="raised", bd=3,
                                     width=12, height=2, command=self.register)
        self.register_btn.pack(side="left", padx=5)
        
        self.exit_btn = tk.Button(btn_frame, text="EXIT", bg=SECONDARY_COLOR, fg=ERROR_COLOR,
                                 font=("Courier", 10, "bold"), relief="raised", bd=3,
                                 width=12, height=2, command=self.root.quit)
        self.exit_btn.pack(side="left", padx=5)
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.login())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
            
    def login(self):
        """Handle login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_label.config(text="Enter username and password", fg=ERROR_COLOR)
            return
            
        success, message = self.user_manager.authenticate_user(username, password)
        
        if success:
            self.status_label.config(text="ACCESS GRANTED", fg=SUCCESS_COLOR)
            self.root.after(500, self.grant_access)
        else:
            self.status_label.config(text=message, fg=ERROR_COLOR)
            
    def register(self):
        """Handle user registration"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username:
            self.status_label.config(text="Enter username to register", fg=ERROR_COLOR)
            return
            
        if not password:
            self.status_label.config(text="Enter password to register", fg=ERROR_COLOR)
            return
            
        success, message = self.user_manager.register_user(username, password)
        self.status_label.config(text=message, 
                                fg=SUCCESS_COLOR if success else ERROR_COLOR)
        
        if success:
            self.root.after(1000, lambda: self.status_label.config(
                text="Registration successful! Now login with your credentials", 
                fg=SUCCESS_COLOR))
            
    def grant_access(self):
        """Grant access to main application"""
        self.root.destroy()
        app = MainApplication(self.user_manager)