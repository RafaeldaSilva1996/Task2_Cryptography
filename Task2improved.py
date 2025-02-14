import os  # Provides functions for interacting with the operating system, such as file handling
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Used to derive cryptographic keys from passwords
from cryptography.hazmat.primitives.hashes import SHA256  # A cryptographic hash function used in key derivation and HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Required for encryption and decryption
from cryptography.hazmat.primitives.padding import PKCS7  # Used to ensure plaintext matches AES block size
from cryptography.hazmat.primitives.hmac import HMAC  # Used for generating and verifying message integrity
from cryptography.hazmat.backends import default_backend  # Specifies the cryptographic backend to use
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For RSA key management
from cryptography.hazmat.primitives import serialization  # For key serialization

# Dictionary storing user passwords
USER_PASSWORDS = {
    "Alice": "alice_secret", # Password for Alice
    "Bob": "bob_secret"   # Password for Bob
}

# Select the user manually
selected_user = "Bob"  # Change to "Bob" to use Bob's key or to "Alice" if "Bob is selected"
PASSWORD = USER_PASSWORDS[selected_user] # Retrieve the password for the selected user

# Get the current working directory to ensure files are created and accessed correctly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Generate unique salt for each user /  Define file paths for user-specific cryptographic artifacts

SALT_FILE = os.path.join(BASE_DIR, f"salt_{selected_user}.bin")  # Salt file used in PBKDF2 key derivation
PRIVATE_KEY_FILE = os.path.join(BASE_DIR, f"private_key_{selected_user}.pem") # RSA Private key file
PUBLIC_KEY_FILE = os.path.join(BASE_DIR, f"public_key_{selected_user}.pem") # RSA Public key file

# Retrieve an existing salt or generate a new one if not found
def get_salt():
    if os.path.exists(SALT_FILE): # Check if the salt file already exists
        with open(SALT_FILE, "rb") as f:  # Open the salt file in read mode to retrieve the stored salt
            return f.read()       # Read and return the existing salt
    else:
        salt = os.urandom(16)  # Generate a new random 16-byte salt
        with open(SALT_FILE, "wb") as f: 
            f.write(salt)   # Store the new salt in a file
        return salt

# Generate an AES-256 encryption key from a password and salt using PBKDF2
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),   # SHA-256 is used as the key derivation function
        length=32,  # 32-byte key for AES-256
        salt=salt, # Unique salt ensures different keys for each user
        iterations=100000,  # High iteration count for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())          # Convert password to bytes and derive the key

# Generate RSA key pair (2048-bit) for encrypting the AES key
def generate_rsa_keys():  # Generate RSA key pair for encrypting AES key
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE): # Check if RSA key files already exist to avoid overwriting
        private_key = rsa.generate_private_key(
            public_exponent=65537, # Common exponent used for RSA key generation, ensuring compatibility and security
            key_size=2048,  # 2048-bit RSA key size for security / strong encryption
            backend=default_backend()   # Specifies the backend cryptographic engine
        )
        public_key = private_key.public_key()     # Extract the public key from the private key
             # Save the private key to a PEM file in an unencrypted format
        with open(PRIVATE_KEY_FILE, "wb") as f:  # Save the RSA private key to a file in PEM format
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,   # Encode the key using PEM format
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # Standard format for private keys
                encryption_algorithm=serialization.NoEncryption()  # No password encryption for private key leaving as is as the user who execute script should have access to this key rather than encrypting it 
            ))
        # Save the public key to a PEM file
        with open(PUBLIC_KEY_FILE, "wb") as f:  # Save the RSA public key to a file in PEM format
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,      # Encode the key using PEM format
                format=serialization.PublicFormat.SubjectPublicKeyInfo       # Standard format for public keys
            ))

# Load the user's public key from file for encrypting the AES key
def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# Encrypt the AES encryption key using RSA public-key encryption
def encrypt_key(key):  # Encrypt the AES key using RSA public key encryption for secure key storage
    public_key = load_public_key()  # Load the RSA public key from the file
    return public_key.encrypt(  # Encrypt the AES key using RSA-OAEP padding for security
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),  # Use MGF1 with SHA256 for OAEP padding mechanism,
            algorithm=SHA256(),    # naming the algorithm being used here 
            label=None
        )
    )

# Generate an HMAC to ensure file integrity during encryption and decryption
def generate_hmac(data, key):
    h = HMAC(key, SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Verify HMAC integrity before decryption to check if the data has been tampered with
def verify_hmac(data, key, expected_hmac):
    h = HMAC(key, SHA256(), backend=default_backend())
    h.update(data)
    h.verify(expected_hmac)  # Raises an exception if verification fails

# Encrypts text data, adds HMAC for integrity verification, and stores it in a file
def encrypt_file(input_text, output_file, key):
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(input_text.encode()) + padder.finalize()
    
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Initialize AES cipher in CBC mode with the given key and IV
    encryptor = cipher.encryptor()  # Create an encryptor object to handle encryption operations
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()  # Encrypt the padded plaintext
    
    hmac = generate_hmac(ciphertext, key)  # Compute HMAC for integrity
    
    with open(output_file, 'wb') as f:  # Write the encrypted content along with IV and HMAC to the output file
        f.write(iv + ciphertext + hmac)

# Decrypts a file, verifies its integrity using HMAC, and returns the plaintext
def decrypt_file(input_file, key):
    with open(input_file, 'rb') as f:  # Open the encrypted file in read mode to retrieve data for decryption
        data = f.read()     # Read the entire encrypted file contents into a single bytes object
    
    
    iv = data[:16]  # Extract the first 16 bytes of the file as the Initialization Vector (IV) used for AES decryption
    ciphertext = data[16:-32]  # Extract ciphertext (excluding IV and HMAC)
    hmac = data[-32:]  # Extract HMAC &  Extract the last 32 bytes of the file, which contain the HMAC for integrity verification
    
    verify_hmac(ciphertext, key, hmac)  # Verify file integrity before decrypting
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()  # Create a decryptor object to handle decryption operations
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext back to padded plaintext
    
    unpadder = PKCS7(128).unpadder()    # Initialize an unpadder for PKCS7 padding removal to restore original plaintext size
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()  # Remove padding from decrypted plaintext to restore the original message
    
    
    return plaintext.decode() # Decode the plaintext from bytes to a string before returning

if __name__ == "__main__":  # Main execution block to initiate encryption and decryption processes
    generate_rsa_keys()
    salt = get_salt()  # Retrieve or generate a unique salt for the user
    key = generate_key(PASSWORD, salt)  # Generate AES encryption key using password and salt
    encrypted_key = encrypt_key(key)  # Encrypt AES key using RSA public key for secure storage  # Encrypt AES key with RSA
    
    encrypted_folder = os.path.join(BASE_DIR, f"EncryptedSecretFolder_{selected_user}")
    decrypted_folder = os.path.join(BASE_DIR, f"DecryptedSecretFolder_{selected_user}")
    os.makedirs(encrypted_folder, exist_ok=True)  # Ensure encrypted folder exists
    os.makedirs(decrypted_folder, exist_ok=True)  # Ensure decrypted folder exists
    
    secret_message1 = f"This is a secret message for {selected_user} "  # Define secret message for encryption
    secret_message2 = f"This is a secret message for {selected_user} "
    
    encrypted_file1 = os.path.join(encrypted_folder, f"SecretFile1_{selected_user}.enc")  # Define path for the first encrypted file
    encrypted_file2 = os.path.join(encrypted_folder, f"SecretFile2_{selected_user}.enc")  # Define path for the second encrypted file
    
    encrypt_file(secret_message1, encrypted_file1, key)  # Encrypt first secret message and save
    encrypt_file(secret_message2, encrypted_file2, key)  # Encrypt second secret message and save
    
    decrypted_text1 = decrypt_file(encrypted_file1, key)  # Decrypt first encrypted message
    decrypted_text2 = decrypt_file(encrypted_file2, key)  # Decrypt second encrypted message
    
    decrypted_file1 = os.path.join(decrypted_folder, f"SecretFile1_{selected_user}.txt")  # Define path for the first decrypted file
    decrypted_file2 = os.path.join(decrypted_folder, f"SecretFile2_{selected_user}.txt")  # Define path for the second decrypted file
    
    with open(decrypted_file1, 'w') as f:  # Save decrypted first message to a text file
        f.write(decrypted_text1)
    with open(decrypted_file2, 'w') as f:  # Open the second decrypted file in write mode to save the decrypted content  # Save decrypted second message to a text file
        f.write(decrypted_text2)
        print(f"Decrypted files saved in: {decrypted_folder}")  # Notify user of successful decryption




# References : https://gist.github.com/de82a468e62e73805c59af620904c124.git
# https://cryptography.io/en/latest/
# https://cryptobook.nakov.com
