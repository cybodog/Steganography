import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import base64
import zlib
import os
import cv2
import numpy as np
from tkinterdnd2 import TkinterDnD, DND_FILES
import hashlib

class AdvancedDCTSteganography:
    @staticmethod
    def prepare_message_for_embedding(message):
        """
        Prepare message with additional metadata for robust embedding
        
        Format:
        - 32 bits (4 bytes) for message length
        - Message content
        - 32-bit hash for integrity check
        """
        # Encode message
        encoded_message = message.encode('utf-8')
        
        # Calculate content length
        message_length = len(encoded_message)
        
        # Create length prefix (4 bytes)
        length_prefix = message_length.to_bytes(4, byteorder='big')
        
        # Calculate hash of the message
        message_hash = hashlib.sha256(encoded_message).digest()[:4]
        
        # Combine all parts
        full_payload = length_prefix + encoded_message + message_hash
        
        return full_payload

    @staticmethod
    def extract_message_from_payload(payload):
        """
        Extract message from payload with integrity check
        """
        # Extract length (first 4 bytes)
        message_length = int.from_bytes(payload[:4], byteorder='big')
        
        # Extract message content
        message_content = payload[4:4+message_length]
        
        # Extract and verify hash
        original_hash = payload[4+message_length:4+message_length+4]
        calculated_hash = hashlib.sha256(message_content).digest()[:4]
        
        # Verify hash
        if original_hash != calculated_hash:
            raise ValueError("Message integrity check failed")
        
        return message_content.decode('utf-8')

    @staticmethod
    def hide_message_in_dct(image_path, payload, output_path):
        """
        Advanced DCT steganography embedding method
        
        Args:
            image_path (str): Path to input image
            payload (bytes): Message payload to hide
            output_path (str): Path to save steganographic image
        """
        # Read image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"Cannot read image: {image_path}")

        # Convert to YCrCb color space (better for steganography)
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        
        # Work on luminance channel
        y_channel = img_ycrcb[:,:,0]
        
        # Convert payload to binary
        binary_payload = ''.join(format(byte, '08b') for byte in payload)
        
        # Embed message
        height, width = y_channel.shape
        payload_index = 0
        
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                if payload_index >= len(binary_payload):
                    break
                
                # Extract 8x8 block
                block = y_channel[i:i+8, j:j+8]
                
                # Compute DCT
                dct_block = cv2.dct(np.float32(block))
                
                # Embed bits in mid-frequency DCT coefficients
                for k in range(4, 8):
                    for l in range(4, 8):
                        if payload_index < len(binary_payload):
                            # Embed bit in sign of coefficient
                            current_bit = int(binary_payload[payload_index])
                            
                            if current_bit == 0:
                                dct_block[k, l] = -abs(dct_block[k, l])
                            else:
                                dct_block[k, l] = abs(dct_block[k, l])
                            
                            payload_index += 1
                
                # Inverse DCT
                idct_block = cv2.idct(dct_block)
                y_channel[i:i+8, j:j+8] = np.clip(idct_block, 0, 255)
        
        # Reconstruct image
        img_ycrcb[:,:,0] = y_channel
        result_img = cv2.cvtColor(img_ycrcb, cv2.COLOR_YCrCb2BGR)
        
        # Save result
        cv2.imwrite(output_path, result_img)
        
        return payload_index  # Return number of bits embedded

    @staticmethod
    def extract_message_from_dct(image_path):
        """
        Advanced DCT steganography extraction method
        """
        # Read image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"Cannot read image: {image_path}")

        # Convert to YCrCb color space
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        y_channel = img_ycrcb[:,:,0]
        
        # Extract binary payload
        binary_payload = []
        height, width = y_channel.shape
        
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                # Extract 8x8 block
                block = y_channel[i:i+8, j:j+8]
                
                # Compute DCT
                dct_block = cv2.dct(np.float32(block))
                
                # Extract bits from mid-frequency coefficients
                for k in range(4, 8):
                    for l in range(4, 8):
                        # Extract bit based on sign of coefficient
                        bit = 1 if dct_block[k, l] > 0 else 0
                        binary_payload.append(str(bit))
        
        # Convert binary to bytes
        binary_str = ''.join(binary_payload)
        payload_bytes = bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
        
        return payload_bytes

class AESSteganography:
    def __init__(self, pin):
        self.pin = pin

    def generate_key(self, salt=None):
        if salt is None:
            salt = os.urandom(16)
        key = PBKDF2(self.pin.encode(), salt, dkLen=32)
        return key, salt

    def encrypt_message(self, message):
        key, salt = self.generate_key()
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        compressed_message = zlib.compress(message.encode())
        encrypted_message = cipher.encrypt(pad(compressed_message, AES.block_size))
        return base64.b64encode(salt + iv + encrypted_message).decode()

    def decrypt_message(self, encrypted_message):
        try:
            data = base64.b64decode(encrypted_message)
            salt = data[:16]
            iv = data[16:32]
            encrypted_data = data[32:]
            key, _ = self.generate_key(salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decompressed_message = zlib.decompress(unpad(cipher.decrypt(encrypted_data), AES.block_size))
            return decompressed_message.decode()
        except Exception as e:
            raise ValueError("Decryption failed. Ensure the correct PIN is used.")

class SteganographyApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Steganography Tool")
        self.geometry("600x700")
        self.configure(bg='#2c3e50')
        self.create_widgets()

    def create_widgets(self):
        # Title
        ttk.Label(self, text="AES Steganography Tool", font=('Helvetica', 18, 'bold'), foreground='white', background='#2c3e50').pack(pady=20)

        # PIN Entry
        pin_frame = ttk.Frame(self)
        pin_frame.pack(pady=10)
        ttk.Label(pin_frame, text="Enter PIN:", background='#2c3e50', foreground='white').pack(side=tk.LEFT, padx=5)
        self.pin_entry = ttk.Entry(pin_frame, show="*", width=30)
        self.pin_entry.pack(side=tk.LEFT, padx=5)

        # Message Entry
        ttk.Label(self, text="Enter Message:", background='#2c3e50', foreground='white').pack(pady=5)
        self.message_entry = tk.Text(self, height=5, width=50)
        self.message_entry.pack(pady=5)

        # Steganography Technique Selection
        technique_frame = ttk.Frame(self)
        technique_frame.pack(pady=10)
        ttk.Label(technique_frame, text="Select Steganography Technique:", background='#2c3e50', foreground='white').pack(side=tk.LEFT, padx=5)
        
        self.technique_var = tk.StringVar(value="lsb")
        technique_options = [
            ("LSB (Least Significant Bit)", "lsb"),
            ("DCT (Discrete Cosine Transform)", "dct")
        ]
        for text, value in technique_options:
            ttk.Radiobutton(technique_frame, text=text, variable=self.technique_var, value=value, 
                             style='TRadiobutton').pack(side=tk.LEFT, padx=5)

        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Hide Message", command=self.hide_message).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Extract Message", command=self.extract_message).pack(side=tk.LEFT, padx=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", length=300)
        self.progress.pack(pady=10)

        # Status Label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self, textvariable=self.status_var, background='#2c3e50', foreground='white')
        self.status_label.pack(pady=10)

    def validate_input(self):
        pin = self.pin_entry.get()
        if not pin or len(pin) < 6:
            messagebox.showerror("Error", "Please enter a PIN with at least 6 characters.")
            return False
        return True

    def hide_message(self):
        if not self.validate_input():
            return

        # Select input image
        image_path = filedialog.askopenfilename(
            filetypes=[
                ("PNG Files", "*.png"),
                ("BMP Files", "*.bmp"),
                ("TIFF Files", "*.tiff"),
                ("JPEG Files", "*.jpg *.jpeg")
            ]
        )
        if not image_path:
            return

        # Select output image
        output_image_path = filedialog.asksaveasfilename(
            defaultextension=".png", 
            filetypes=[("PNG Files", "*.png")]
        )
        if not output_image_path:
            return

        pin = self.pin_entry.get()
        message = self.message_entry.get("1.0", tk.END).strip()
        technique = self.technique_var.get()

        if not message:
            messagebox.showerror("Error", "Please enter a message to hide.")
            return

        try:
            self.progress.start()
            self.status_var.set("Hiding message...")
            self.update_idletasks()

            if technique == 'lsb':
                self.hide_lsb(image_path, message, output_image_path)
            elif technique == 'dct':
                self.hide_dct(image_path, message, output_image_path)

            messagebox.showinfo("Success", f"Message hidden successfully in {output_image_path}")
            self.status_var.set("Message hidden successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Failed to hide message.")
        finally:
            self.progress.stop()

    def hide_lsb(self, image_path, message, output_image_path):
        aes_steg = AESSteganography(self.pin_entry.get())
        encrypted_message = aes_steg.encrypt_message(message)
        binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message) + '1111111111111110'

        image = Image.open(image_path)
        pixels = list(image.getdata())
        new_pixels = []
        binary_index = 0

        for pixel in pixels:
            if binary_index < len(binary_message):
                pixel = list(pixel)
                for i in range(3):
                    if binary_index < len(binary_message):
                        pixel[i] = pixel[i] & ~1 | int(binary_message[binary_index])
                        binary_index += 1
                new_pixels.append(tuple(pixel))
            else:
                new_pixels.append(pixel)

        # Create a new image with modified pixels
        new_image = Image.new(image.mode, image.size)
        new_image.putdata(new_pixels)
        new_image.save(output_image_path)

    def hide_dct(self, image_path, message, output_image_path):
        try:
            # Encrypt the message
            aes_steg = AESSteganography(self.pin_entry.get())
            encrypted_message = aes_steg.encrypt_message(message)

            # Prepare payload
            payload = AdvancedDCTSteganography.prepare_message_for_embedding(encrypted_message)

            # Hide message
            bits_embedded = AdvancedDCTSteganography.hide_message_in_dct(
                image_path, payload, output_image_path
            )

            print(f"[DEBUG] Embedded {bits_embedded} bits")
            return True

        except Exception as e:
            print(f"[DEBUG] DCT Hiding Error: {e}")
            return False

    def extract_message(self):
        if not self.validate_input():
            return

        # Select input image
        image_path = filedialog.askopenfilename(
            filetypes=[
                ("PNG Files", "*.png"),
                ("BMP Files", "*.bmp"),
                ("TIFF Files", "*.tiff"),
                ("JPEG Files", "*.jpg *.jpeg")
            ]
        )
        if not image_path:
            return

        pin = self.pin_entry.get()
        technique = self.technique_var.get()

        try:
            self.progress.start()
            self.status_var.set("Extracting message...")
            self.update_idletasks()

            if technique == 'lsb':
                encrypted_message = self.extract_lsb(image_path)
            elif technique == 'dct':
                encrypted_message = self.extract_dct(image_path)
            else:
                raise ValueError("Invalid technique selected.")

            aes_steg = AESSteganography(pin)
            decrypted_message = aes_steg.decrypt_message(encrypted_message)
            
            messagebox.showinfo("Hidden Message", decrypted_message)
            self.status_var.set("Message extracted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Failed to extract message.")
        finally:
            self.progress.stop()

    def extract_lsb(self, image_path):
        image = Image.open(image_path)
        pixels = list(image.getdata())
        binary_message = ''

        for pixel in pixels:
            for color in pixel[:3]:
                binary_message += str(color & 1)
                if binary_message[-16:] == '1111111111111110':
                    extracted_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message)-16, 8))
                    return extracted_message

        raise ValueError("No hidden message found.")

    def extract_dct(self, image_path):
        try:
            # Extract payload
            payload_bytes = AdvancedDCTSteganography.extract_message_from_dct(image_path)

            # Convert payload to encrypted message
            encrypted_message = AdvancedDCTSteganography.extract_message_from_payload(payload_bytes)

            return encrypted_message

        except Exception as e:
            print(f"[DEBUG] DCT Extraction Error: {e}")
            raise ValueError("Failed to extract message. Check PIN or image.")

def setup_styles(root):
    """
    Set up custom styles for the application
    """
    style = ttk.Style()
    style.theme_use('clam')
    
    # Configure button styles
    style.configure('TButton', 
                    background='#3498db', 
                    foreground='white', 
                    font=('Helvetica', 10))
    
    # Configure entry styles
    style.configure('TEntry', 
                    background='white', 
                    foreground='black')
    
    # Configure radiobutton styles
    style.configure('TRadiobutton', 
                    background='#2c3e50', 
                    foreground='white')

if __name__ == "__main__":
    try:
        # Create root window
        root = TkinterDnD.Tk()
        
        # Setup custom styles
        setup_styles(root)
        
        # Create and run the application
        app = SteganographyApp()
        app.mainloop()
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()