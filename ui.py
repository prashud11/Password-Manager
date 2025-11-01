import os, secrets, string, tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from storage import init_db, get_meta, set_meta, add_entry, list_entries, delete_entry
from crypto_utils import derive_key, encrypt, decrypt

def _random_password(n=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+[]{}"
    return "".join(secrets.choice(alphabet) for _ in range(n))

def _ensure_master_key(root) -> bytes:
    """Create or validate master password, return Fernet key."""
    init_db()
    salt = get_meta("salt")
    pwd_hash = get_meta("pwd_hash")

    if salt is None:
        # First run. Set master password.
        while True:
            p1 = simpledialog.askstring("Set Master Password", "Enter a strong master password:", show="*")
            if not p1:
                raise SystemExit("Setup cancelled")
            p2 = simpledialog.askstring("Confirm", "Re-enter master password:", show="*")
            if p1 != p2:
                messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
                continue
            # Generate salt and store hash of derived key for validation
            salt = os.urandom(16)
            key = derive_key(p1, salt)
            # store a short hash of the key for quick verification
            import hashlib
            key_hash = hashlib.sha256(key).digest()
            set_meta("salt", salt)
            set_meta("pwd_hash", key_hash)
            messagebox.showinfo("Success", "Master password set. Keep it safe. There is no recovery.")
            return key
    else:
        # Existing vault. Ask for password and verify.
        for _ in range(3):
            pw = simpledialog.askstring("Unlock Vault", "Enter master password:", show="*")
            if not pw:
                raise SystemExit("Login cancelled")
            key = derive_key(pw, salt)
            import hashlib
            if hashlib.sha256(key).digest() == pwd_hash:
                return key
            messagebox.showerror("Invalid", "Incorrect master password.")
        raise SystemExit("Too many attempts. Exiting.")

def _refresh(tree, fkey):
    for i in tree.get_children():
        tree.delete(i)
    for row_id, site, username, enc_pw in list_entries():
        try:
            pw = decrypt(enc_pw, fkey)
        except Exception:
            pw = "<decrypt error>"
        tree.insert("", "end", iid=str(row_id), values=(site, username, pw))

def run_app():
    root = tk.Tk()
    root.title("Password Manager - Starter")
    root.geometry("680x420")

    try:
        fkey = _ensure_master_key(root)
    except SystemExit:
        root.destroy()
        return

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    cols = ("site", "username", "password")
    tree = ttk.Treeview(frm, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=c.title())
        tree.column(c, width=200 if c != "password" else 220)
    tree.pack(fill="both", expand=True)

    btns = ttk.Frame(frm); btns.pack(fill="x", pady=8)

    def add_item():
        site = simpledialog.askstring("Site", "Site or App:")
        if not site: return
        user = simpledialog.askstring("Username", "Username or Email:")
        if user is None: return
        pw = simpledialog.askstring("Password", "Password (leave empty to generate):", show="*")
        if not pw:
            pw = _random_password(16)
            messagebox.showinfo("Generated", f"Generated password:\n{pw}")
        enc = encrypt(pw, fkey)
        add_entry(site, user, enc)
        _refresh(tree, fkey)

    def copy_pw():
        sel = tree.focus()
        if not sel:
            messagebox.showwarning("Select", "Select a row first.")
            return
        pw = tree.item(sel)["values"][2]
        root.clipboard_clear()
        root.clipboard_append(pw)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def delete_sel():
        sel = tree.focus()
        if not sel:
            messagebox.showwarning("Select", "Select a row first.")
            return
        if messagebox.askyesno("Confirm", "Delete this entry?"):
            delete_entry(int(sel))
            _refresh(tree, fkey)

    ttk.Button(btns, text="Add", command=add_item).pack(side="left")
    ttk.Button(btns, text="Copy Password", command=copy_pw).pack(side="left", padx=8)
    ttk.Button(btns, text="Delete", command=delete_sel).pack(side="left")

    _refresh(tree, fkey)
    root.mainloop()
