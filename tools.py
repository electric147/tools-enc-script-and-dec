from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pkcs7
from cryptography.hazmat.backends import default_backend
import base64
import os

# Fungsi untuk RSA Enkripsi dan Dekripsi
def rsa_encrypt_decrypt(text, private_key, public_key, mode):
    if mode == "enc":
        ciphertext = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')
    elif mode == "dec":
        plaintext = private_key.decrypt(
            base64.b64decode(text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')

# Fungsi untuk AES Enkripsi dan Dekripsi (CBC Mode)
def aes_encrypt_decrypt(text, key, mode):
    if mode == "enc":
        # AES Enkripsi
        cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = pkcs7.PKCS7(128).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')
    elif mode == "dec":
        # AES Dekripsi
        cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(base64.b64decode(text)) + decryptor.finalize()
        unpadder = pkcs7.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')

# Fungsi untuk Vigenère Cipher
def vigenere_encrypt_decrypt(text, key, mode):
    result = []
    key = key.lower()
    text = text.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if mode == "enc":
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            elif mode == "dec":
                result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

# Fungsi untuk XOR Cipher
def xor_encrypt_decrypt(text, key, mode):
    result = []
    for i in range(len(text)):
        result.append(chr(ord(text[i]) ^ key))
    return ''.join(result)

# Fungsi untuk Blowfish Enkripsi dan Dekripsi
def blowfish_encrypt_decrypt(text, key, mode):
    cipher = Cipher(algorithms.Blowfish(key.encode()), modes.CBC(os.urandom(8)), backend=default_backend())
    if mode == "enc":
        encryptor = cipher.encryptor()
        padder = pkcs7.PKCS7(128).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')
    elif mode == "dec":
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(base64.b64decode(text)) + decryptor.finalize()
        unpadder = pkcs7.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')

# Fungsi untuk menampilkan penjelasan metode enkripsi
def show_help():
    help_text = """
    1. RSA Enkripsi/Dekripsi:
       - RSA adalah algoritma kunci publik yang sangat aman.
       - Menggunakan padding OAEP dengan algoritma hash SHA-256 untuk mengamankan data.
       - Enkripsi dan dekripsi hanya dapat dilakukan dengan kunci yang sesuai.

    2. AES Enkripsi/Dekripsi (CBC Mode):
       - AES adalah algoritma simetris dengan kunci yang panjangnya 16, 24, atau 32 byte.
       - Mode CBC (Cipher Block Chaining) memastikan setiap blok data terenkripsi dengan cara yang aman.
       - Enkripsi dan dekripsi memerlukan kunci yang sama.

    3. Vigenère Cipher:
       - Teknik enkripsi klasik menggunakan kata kunci untuk menggeser karakter.
       - Metode ini sederhana dan dapat digunakan untuk mengenkripsi pesan pendek.

    4. XOR Cipher:
       - XOR adalah algoritma enkripsi simetris menggunakan operasi logika XOR.
       - Setiap karakter dienkripsi dengan cara XOR dengan kunci yang diberikan.

    5. Blowfish Cipher:
       - Blowfish adalah algoritma enkripsi simetris dengan blok 64 bit.
       - Cepat dan aman, sangat baik untuk data besar dan aplikasi yang membutuhkan enkripsi yang kuat.
    """
    print(help_text)

# Fungsi untuk menampilkan menu dan menjalankan program utama
def main():
    private_key, public_key = generate_rsa_keys()

    while True:
        print("Wallcome To Tools By Electric Jang Lupa Supcribe Yt ELECTRIC BLUE BOTZ")
        print("\nPilih metode enkripsi/dekripsi:")
        print("1. RSA Enkripsi/Dekripsi")
        print("2. AES Enkripsi/Dekripsi (CBC Mode)")
        print("3. Vigenère Cipher")
        print("4. XOR Cipher")
        print("5. Blowfish Cipher")
        print("6. Bantuan (Help)")
        print("7. Keluar")
        
        pilihan = input("Masukkan nomor pilihan Anda (1-7): ")

        if pilihan == '1':
            print("RSA Enkripsi/Dekripsi:")
            mode = input("Apakah Anda ingin Enkripsi (enc) atau Dekripsi (dec)? ")
            text = input("Masukkan teks: ")
            result = rsa_encrypt_decrypt(text, private_key, public_key, mode)
            print(f"Hasil: {result}")

        elif pilihan == '2':
            print("AES Enkripsi/Dekripsi (CBC Mode):")
            key = input("Masukkan kunci AES (16, 24, atau 32 byte): ").encode()
            if len(key) not in [16, 24, 32]:
                print("Panjang kunci tidak valid! Harus 16, 24, atau 32 byte.")
                continue
            mode = input("Apakah Anda ingin Enkripsi (enc) atau Dekripsi (dec)? ")
            text = input("Masukkan teks: ")
            result = aes_encrypt_decrypt(text, key, mode)
            print(f"Hasil: {result}")

        elif pilihan == '3':
            print("Vigenère Cipher:")
            mode = input("Apakah Anda ingin Enkripsi (enc) atau Dekripsi (dec)? ")
            text = input("Masukkan teks: ")
            key = input("Masukkan kata kunci (string): ")
            result = vigenere_encrypt_decrypt(text, key, mode)
            print(f"Hasil: {result}")

        elif pilihan == '4':
            print("XOR Cipher:")
            mode = input("Apakah Anda ingin Enkripsi (enc) atau Dekripsi (dec)? ")
            text = input("Masukkan teks: ")
            key = int(input("Masukkan kunci (angka): "))
            result = xor_encrypt_decrypt(text, key, mode)
            print(f"Hasil: {result}")

        elif pilihan == '5':
            print("Blowfish Cipher:")
            mode = input("Apakah Anda ingin Enkripsi (enc) atau Dekripsi (dec)? ")
            text = input("Masukkan teks: ")
            key = input("Masukkan kunci Blowfish (8 byte): ")
            if len(key) != 8:
                print("Panjang kunci tidak valid! Harus 8 byte.")
                continue
            result = blowfish_encrypt_decrypt(text, key, mode)
            print(f"Hasil: {result}")

        elif pilihan == '6':
            show_help()

        elif pilihan == '7':
            print("Keluar...")
            break
        else:
            print("Pilihan tidak valid. Silakan coba lagi.")

# Fungsi untuk menghasilkan kunci RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Menjalankan program utama
if __name__ == "__main__":
    main()
