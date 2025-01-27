import tkinter as tk
from tkinter import messagebox
import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa

class BlindSignature:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        numbers = self.private_key.private_numbers()
        self.n = self.private_key.private_numbers().public_numbers.n
        self.e = numbers.public_numbers.e
        self.d = self.private_key.private_numbers().d
        
        # Store intermediate values
        self.blinding_factor = None
        self.blinded_message = None
        self.blind_signature = None
        self.final_signature = None

    def blind_message(self, message):
        """
        Blind the message using a random blinding factor
        """
        # Convert message to integer
        message_int = int.from_bytes(message.encode(), 'big')
        
        # Generate random blinding factor
        while True:
            self.blinding_factor = random.randrange(2, self.n)
            if math.gcd(self.blinding_factor, self.n) == 1:
                break
        
        # Blind the message: m' = m * r^e mod n
        self.blinded_message = (message_int * pow(self.blinding_factor, self.e, self.n)) % self.n
        return self.blinded_message

    def sign_blinded(self):
        """
        Sign the blinded message using private key
        """
        if self.blinded_message is None:
            raise ValueError("No blinded message to sign")
        
        # Sign: s' = (m')^d mod n
        self.blind_signature = pow(self.blinded_message, self.d, self.n)
        return self.blind_signature

    def unblind(self):
        """
        Unblind the signature
        """
        if self.blind_signature is None or self.blinding_factor is None:
            raise ValueError("Missing blind signature or blinding factor")
        
        # Unblind: s = s' * r^(-1) mod n
        r_inv = pow(self.blinding_factor, -1, self.n)
        self.final_signature = (self.blind_signature * r_inv) % self.n
        return self.final_signature

    def verify(self, message, signature):
        """
        Verify the signature
        """
        message_int = int.from_bytes(message.encode(), 'big')
        # Verify: m = s^e mod n
        verification = pow(signature, self.e, self.n)
        return verification == message_int

class BlindSignatureGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RSA Blind Signature Demo")
        self.root.geometry("600x800")
        
        self.blind_signature = BlindSignature()
        self.setup_gui()

    def setup_gui(self):
        # Message Input
        tk.Label(self.root, text="Enter Message:", font=("Arial", 12)).pack(pady=10)
        self.message_entry = tk.Entry(self.root, font=("Arial", 14), width=40)
        self.message_entry.pack(pady=5)

        # Status Display
        self.status_label = tk.Label(self.root, text="Status: Ready", font=("Arial", 12))
        self.status_label.pack(pady=10)

        # Key Info Display
        key_frame = tk.LabelFrame(self.root, text="Key Information", font=("Arial", 12))
        key_frame.pack(pady=10, padx=10, fill="x")
        
        self.key_info = tk.Text(key_frame, height=6, font=("Courier", 10))
        self.key_info.pack(pady=5, padx=5, fill="x")
        self.update_key_info()

        # Operation Buttons
        tk.Button(self.root, text="Blind Message", command=self.blind_message).pack(pady=5)
        tk.Button(self.root, text="Sign Blinded Message", command=self.sign_blinded).pack(pady=5)
        tk.Button(self.root, text="Unblind Signature", command=self.unblind).pack(pady=5)
        tk.Button(self.root, text="Verify Signature", command=self.verify).pack(pady=5)

        # Results Display
        self.results_text = tk.Text(self.root, height=15, font=("Courier", 10))
        self.results_text.pack(pady=10, padx=10, fill="both", expand=True)

    def update_key_info(self):
        self.key_info.delete(1.0, tk.END)
        self.key_info.insert(tk.END, f"Public Exponent (e): {self.blind_signature.e}\n")
        self.key_info.insert(tk.END, f"Modulus (n): {str(self.blind_signature.n)[:50]}...\n")

    def blind_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Please enter a message")
            return
        
        try:
            blinded = self.blind_signature.blind_message(message)
            self.status_label.config(text="Status: Message Blinded")
            self.results_text.insert(tk.END, f"Blinded Message: {str(blinded)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def sign_blinded(self):
        try:
            signature = self.blind_signature.sign_blinded()
            self.status_label.config(text="Status: Blinded Message Signed")
            self.results_text.insert(tk.END, f"Blind Signature: {str(signature)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def unblind(self):
        try:
            final_sig = self.blind_signature.unblind()
            self.status_label.config(text="Status: Signature Unblinded")
            self.results_text.insert(tk.END, f"Final Signature: {str(final_sig)[:50]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify(self):
        message = self.message_entry.get()
        try:
            if self.blind_signature.verify(message, self.blind_signature.final_signature):
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