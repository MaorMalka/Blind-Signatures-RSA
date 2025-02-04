import tkinter as tk
from tkinter import messagebox
import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature


class SchnorrBlindSignature:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.k = None
        self.R = None
        self.alpha = None  # גורם עיוורון (blinding factor)
        self.R_prime = None
        self.e_prime = None
        self.s_prime = None
        self.final_signature = None

    def generate_k(self):
        """הצד החותם מייצר nonce k ושולח את R = kG למשתמש."""
        self.k = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.R = self.k.public_key()
        return self.R.public_numbers().x, self.R.public_numbers().y

    def blind_message(self, message):
        """המשתמש מעוורר את ההודעה באמצעות α."""
        if self.R is None:
            raise ValueError("יש לייצר R קודם (קראו ל-generate_k)")
        
        self.alpha = random.randrange(1, self.order)
        
        # מחשבים R' = αR
        self.R_prime = self._scalar_multiply(self.R, self.alpha)
        
        # מחשבים e = H(R' || m)
        R_prime_bytes = self.point_to_bytes(self.R_prime)
        e = int.from_bytes(hashlib.sha256(R_prime_bytes + message.encode()).digest(), 'big') % self.order
        
        # מחשבים e' = α⁻¹ * e
        alpha_inv = pow(self.alpha, -1, self.order)
        self.e_prime = (alpha_inv * e) % self.order
        return self.e_prime

    def sign_blinded(self):
        """הצד החותם מחשב s' = k + e'd."""
        if self.e_prime is None:
            raise ValueError("אין אתגר מעורפלת לחתימה")
        
        d = self.private_key.private_numbers().private_value
        self.s_prime = (self.k.private_numbers().private_value + self.e_prime * d) % self.order
        return self.s_prime

    def unblind(self):
        """המשתמש מחשב s = α * s' להסרת העיוורון."""
        if self.s_prime is None:
            raise ValueError("חסרה s' להסרת העיוורון")
        
        self.final_signature = (self.alpha * self.s_prime) % self.order
        return self.final_signature

    def verify(self, message):
        """אימות: sG = R' + eP."""
        if self.final_signature is None:
            raise ValueError("אין חתימה לאימות")
        
        # מחשבים מחדש e = H(R' || m)
        R_prime_bytes = self.point_to_bytes(self.R_prime)
        e = int.from_bytes(hashlib.sha256(R_prime_bytes + message.encode()).digest(), 'big') % self.order
        
        # מחשבים sG ו־R' + eP
        sG = self._scalar_multiply(self._get_generator(), self.final_signature)
        eP = self._scalar_multiply(self.public_key, e)
        R_prime_plus_eP = self._point_add(self.R_prime, eP)
        
        return (
            sG.public_numbers().x == R_prime_plus_eP.public_numbers().x and
            sG.public_numbers().y == R_prime_plus_eP.public_numbers().y
        )

    def _get_generator(self):
        """מחזיר את נקודת הגנרטור של SECP256K1"""
        return ec.EllipticCurvePublicNumbers(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            ec.SECP256K1()
        ).public_key(default_backend())

    def _scalar_multiply(self, point, scalar):
        """מכפלה סקלרית בנקודה (אלגוריתם double-and-add)"""
        result = None
        for bit in bin(scalar)[2:]:
            result = self._point_double(result) if result else None
            if bit == '1':
                result = self._point_add(result, point) if result else point
        return result

    def _point_double(self, point):
        """כפל נקודה בעצמה (point doubling)"""
        return self._point_add(point, point)

    def _point_add(self, point1, point2):
        """חיבור שתי נקודות על העקומה האליפטית"""
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1.public_numbers().x, point1.public_numbers().y
        x2, y2 = point2.public_numbers().x, point2.public_numbers().y

        if x1 == x2:
            if y1 == y2:
                # חיבור של אותו נקודה – כפל
                slope = (3 * x1 * x1) * pow(2 * y1, -1, self._get_p()) % self._get_p()
            else:
                # נקודות אנכיות – התוצאה היא אינסוף
                return None
        else:
            # חיבור רגיל
            slope = (y2 - y1) * pow(x2 - x1, -1, self._get_p()) % self._get_p()

        x3 = (slope**2 - x1 - x2) % self._get_p()
        y3 = (slope * (x1 - x3) - y1) % self._get_p()
        return ec.EllipticCurvePublicNumbers(x3, y3, ec.SECP256K1()).public_key(default_backend())

    def _get_p(self):
        """המודול הראשוני עבור SECP256K1"""
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def point_to_bytes(self, point):
        """המרת נקודה לבייטים (פורמט לא דחוס)"""
        return point.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    

class RSABlindSignature:
    def __init__(self):
        # יצירת זוג מפתחות עבור RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        numbers = self.private_key.private_numbers()
        self.n = numbers.public_numbers.n
        self.e = numbers.public_numbers.e
        self.d = numbers.d
        
        # משתנים לאחסון ערכים ביניים
        self.blinding_factor = None
        self.blinded_message = None
        self.blind_signature = None
        self.final_signature = None

    def _hash_message(self, message):
        """גיבוב ההודעה באמצעות SHA-256 והמרתה למספר"""
        message_hash = hashlib.sha256(message.encode()).digest()
        return int.from_bytes(message_hash, 'big')

    def blind_message(self, message):
        """
        עיוורון ההודעה באמצעות גורם עיוורון רנדומלי.
        ראשית גובשים את ההודעה כך שהמספר יהיה קטן.
        """
        # המרת ההודעה למספר באמצעות גיבוב SHA-256
        message_int = self._hash_message(message)
        
        # יצירת גורם עיוורון רנדומלי
        while True:
            self.blinding_factor = random.randrange(2, self.n)
            if math.gcd(self.blinding_factor, self.n) == 1:
                break
        
        # עיוורון ההודעה: m' = m * r^e mod n
        self.blinded_message = (message_int * pow(self.blinding_factor, self.e, self.n)) % self.n
        return self.blinded_message

    def sign_blinded(self):
        """
        חתימה על ההודעה המעורפלת באמצעות המפתח הפרטי.
        """
        if self.blinded_message is None:
            raise ValueError("אין הודעה מעורפלת לחתימה")
        
        # חתימה: s' = (m')^d mod n
        self.blind_signature = pow(self.blinded_message, self.d, self.n)
        return self.blind_signature

    def unblind(self):
        """
        הסרת העיוורון מהחתימה.
        """
        if self.blind_signature is None or self.blinding_factor is None:
            raise ValueError("חסרה חתימה מעורפלת או גורם עיוורון")
        
        # הסרת עיוורון: s = s' * r^(-1) mod n
        r_inv = pow(self.blinding_factor, -1, self.n)
        self.final_signature = (self.blind_signature * r_inv) % self.n
        return self.final_signature

    def verify(self, message, signature):
        """
        אימות החתימה.
        """
        # גיבוב ההודעה
        message_int = self._hash_message(message)
        # אימות: m = s^e mod n
        verification = pow(signature, self.e, self.n)
        return verification == message_int


class BlindSignatureGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Blind Signature Demo")
        self.root.geometry("600x800")
        
        # משתנים עבור שני סוגי החתימות
        self.rsa_blind_signature = RSABlindSignature()  # RSA Blind Signature
        self.schnorr_blind_signature = SchnorrBlindSignature()  # Schnorr Blind Signature
        self.current_scheme = "RSA"  # ברירת מחדל – RSA Blind Signature
        self.setup_gui()

    def setup_gui(self):
        # בחירת שיטת חתימה
        scheme_frame = tk.LabelFrame(self.root, text="Signature Scheme", font=("Arial", 12))
        scheme_frame.pack(pady=10, padx=10, fill="x")
        
        # עדכון תוויות הבחירה כך שישקפו את סוג החתימה
        self.scheme_var = tk.StringVar(value="RSA")
        tk.Radiobutton(scheme_frame, text="RSA Blind Signature", variable=self.scheme_var, 
                      value="RSA", command=self.switch_scheme).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(scheme_frame, text="Schnorr Blind Signature", variable=self.scheme_var, 
                      value="Schnorr", command=self.switch_scheme).pack(side=tk.LEFT, padx=10)
        
        # כפתור לייצור k (רלוונטי רק עבור Schnorr)
        self.generate_k_button = tk.Button(self.root, text="Generate k (Required for Schnorr)", 
                                     command=self.generate_k)
        self.blind_message_button = tk.Button(self.root, text="Blind Message", 
                                    command=self.blind_message)
        self.sign_button = tk.Button(self.root, text="Sign Blinded Message", 
                                    command=self.sign_blinded)
        self.unblind_button = tk.Button(self.root, text="Unblind Signature", 
                                   command=self.unblind)
        self.verify_button = tk.Button(self.root, text="Verify Signature", 
                                  command=self.verify)
        
        # קלט הודעה
        tk.Label(self.root, text="Enter Message:", font=("Arial", 12)).pack(pady=10)
        self.message_entry = tk.Entry(self.root, font=("Arial", 14), width=40)
        self.message_entry.pack(pady=5)

        # תצוגת סטטוס
        self.status_label = tk.Label(self.root, text="Status: Ready", font=("Arial", 12))
        self.status_label.pack(pady=10)

        # תצוגת מידע על המפתחות
        key_frame = tk.LabelFrame(self.root, text="Key Information", font=("Arial", 12))
        key_frame.pack(pady=10, padx=10, fill="x")
        
        self.key_info = tk.Text(key_frame, height=6, font=("Courier", 10))
        self.key_info.pack(pady=5, padx=5, fill="x")
        self.update_key_info()

        # אריזת כפתורים
        self.blind_message_button.pack(pady=5)
        self.sign_button.pack(pady=5)
        self.unblind_button.pack(pady=5)
        self.verify_button.pack(pady=5)

        # תצוגת תוצאות
        self.results_text = tk.Text(self.root, height=15, font=("Courier", 10))
        self.results_text.pack(pady=10, padx=10, fill="both", expand=True)

    def switch_scheme(self):
        self.current_scheme = self.scheme_var.get()
        if self.current_scheme == "Schnorr":
            # הצגת כפתור generate_k עבור Schnorr
            self.generate_k_button.pack(before=self.blind_message_button, pady=5)
            self.status_label.config(text="Status: Ready (Generate k first for Schnorr)")
        else:
            self.generate_k_button.pack_forget()
            self.status_label.config(text="Status: Ready")
    
        # ניקוי תוצאות ועדכון מידע על מפתחות
        self.results_text.delete(1.0, tk.END)
        self.update_key_info()

    def generate_k(self):
        try:
            R_x, R_y = self.schnorr_blind_signature.generate_k()
            self.status_label.config(text="Status: Generated k")
            self.results_text.insert(tk.END, f"Generated R point: ({str(R_x)[:20]}..., {str(R_y)[:20]}...)\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def blind_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Please enter a message")
            return
        
        try:
            if self.current_scheme == "RSA":
                blinded = self.rsa_blind_signature.blind_message(message)
            else:
                # בדיקה האם נוצר k עבור Schnorr
                if self.schnorr_blind_signature.R is None:
                    messagebox.showerror("Error", "Please generate k first (click 'Generate k' button)")
                    return
                blinded = self.schnorr_blind_signature.blind_message(message)
            
            self.status_label.config(text="Status: Message Blinded")
            self.results_text.insert(tk.END, f"Blinded Message: {str(blinded)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_key_info(self):
        self.key_info.delete(1.0, tk.END)
        if self.current_scheme == "RSA":
            self.key_info.insert(tk.END, f"Public Exponent (e): {self.rsa_blind_signature.e}\n")
            self.key_info.insert(tk.END, f"Modulus (n): {str(self.rsa_blind_signature.n)[:50]}...\n")
        else:
            # תצוגת מידע עבור Schnorr
            point_bytes = self.schnorr_blind_signature.point_to_bytes(self.schnorr_blind_signature.public_key)
            pubkey_x = int.from_bytes(point_bytes[1:33], 'big')
            pubkey_y = int.from_bytes(point_bytes[33:], 'big')
            self.key_info.insert(tk.END, f"Curve: SECP256K1\n")
            self.key_info.insert(tk.END, f"Public Key X: {str(pubkey_x)[:50]}...\n")
            self.key_info.insert(tk.END, f"Public Key Y: {str(pubkey_y)[:50]}...\n")

    def sign_blinded(self):
        try:
            if self.current_scheme == "RSA":
                signature = self.rsa_blind_signature.sign_blinded()
            else:
                signature = self.schnorr_blind_signature.sign_blinded()
            self.status_label.config(text="Status: Blinded Message Signed")
            self.results_text.insert(tk.END, f"Blind Signature: {str(signature)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def unblind(self):
        try:
            if self.current_scheme == "RSA":
                final_sig = self.rsa_blind_signature.unblind()
            else:
                final_sig = self.schnorr_blind_signature.unblind()
            self.status_label.config(text="Status: Signature Unblinded")
            self.results_text.insert(tk.END, f"Final Signature: {str(final_sig)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify(self):
        message = self.message_entry.get()
        try:
            if self.current_scheme == "RSA":
                signature = self.rsa_blind_signature.final_signature
                result = self.rsa_blind_signature.verify(message, signature)
            else:
                result = self.schnorr_blind_signature.verify(message)
                
            if result:
                self.status_label.config(text="Status: Signature Verified ✅")
                messagebox.showinfo("Success", "Signature verification successful! ✅")
            else:
                self.status_label.config(text="Status: Verification Failed ❌")
                messagebox.showerror("Error", "Signature verification failed ❌")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = BlindSignatureGUI()
    app.run()
