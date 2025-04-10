# download pycryptodome to access crypto libraries 

from Crypto.Cipher import DES    #for DES encryption(56-bit+8 bit error checking key symmetric encryption ) 
import hmac                      # Provides support for generating and verifying HMAC
                                 # Used with hmac to compute a secure HMAC for message authentication
import hashlib                   # to provide hash function (sha1,sha256, ....)
import os                        # we use it to generate nonce and IV in DES
import time                      # for the delay function in the MAC (GENERATE TIMESTAMP)
from Crypto.PublicKey import RSA # assymteric encryption Method (IN OUR CODE, USED TO GENERATE PU AND PR)
from Crypto.Cipher import PKCS1_OAEP, AES #for asymmetric padding and AES encryption (in the digital envelope)
                                          #OAEP is used for secure assymmetric encryption and decryption (RSA)
from Crypto.Random import get_random_bytes #This function generates random keys dor AES encryption 
import base64               # used to encode binary data into an ASCII string format (for better storage)

SHARED_KEY = b"my_secret_key"  # Example shared key (must be kept secret, used in)
##############################################################################################################
# Utility functions for DES encryption and decryption(4)
def pad(text):
    while len(text) % 8 != 0:
        text += '-'
    return text 

def unpad(text):
    return text.rstrip('-')
##############################################################################################################
def encrypt_des(plaintext, key, mode, iv_or_nonce=None):
    cipher = None
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv_or_nonce)
    elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv_or_nonce)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv_or_nonce)
    else:
        raise ValueError("Invalid mode specified")

    padded_text = pad(plaintext)
    ciphertext = cipher.encrypt(padded_text.encode())
    return ciphertext
##############################################################################################################
def decrypt_des(ciphertext, key, mode, iv_or_nonce=None):
    cipher = None
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv_or_nonce)
    elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv_or_nonce)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv_or_nonce)
    else:
        raise ValueError("Invalid mode specified")

    decrypted_text = cipher.decrypt(ciphertext)
    return unpad(decrypted_text.decode())
##############################################################################################################




# Message Authentication Code (MAC) functions(2)
def generate_mac(message, timestamp):
   #Generates a MAC by appending a timestamp to the message and signing it.
    message_with_timestamp = f"{message}|{timestamp}".encode()
    mac = hmac.new(SHARED_KEY, message_with_timestamp, hashlib.sha256).hexdigest()
    return f"{message}|{timestamp}|{mac}"
##############################################################################################################
def verify_mac(received_message_with_mac):
    #Verifies the MAC for the received message.
    try:
        # Split the received message into its components
        message, timestamp, received_mac = received_message_with_mac.rsplit('|', 2)
        timestamp = int(timestamp)

        # Recompute the MAC for verification
        message_with_timestamp = f"{message}|{timestamp}".encode()
        recomputed_mac = hmac.new(SHARED_KEY, message_with_timestamp, hashlib.sha256).hexdigest()

        if hmac.compare_digest(recomputed_mac, received_mac):
            # Check for replay attacks
            current_time = int(time.time())
            if current_time - timestamp > 20:
                return "MAC valid, but replay attack detected."
            return "MAC valid and message authenticated."
        else:
            return "MAC invalid. Message authentication failed."
    except ValueError:
        return "Error: Invalid message format."  #exception handling
    except Exception as e:
        return f"Error during verification: {e}"
##############################################################################################################




# Hybrid encryption functions (Digital Envelope) (3)
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print("Key pair generated and saved to 'private_key.pem' and 'public_key.pem'.")
##############################################################################################################
def hybrid_encrypt(plaintext, receiver_public_key):
    try:
        rsa_key = RSA.import_key(receiver_public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        symmetric_key = get_random_bytes(16)
        aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext = aes_cipher.encrypt(plaintext.encode())

        encrypted_key = rsa_cipher.encrypt(symmetric_key)

        encrypted_data = {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'nonce': base64.b64encode(aes_cipher.nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        }
        return encrypted_data
    except (ValueError, TypeError, Exception) as e:
        raise ValueError("Encryption failed. Please check the input and the public key.") from e
##############################################################################################################
def hybrid_decrypt(encrypted_key_b64, nonce_b64, ciphertext_b64, receiver_private_key):
    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        rsa_key = RSA.import_key(receiver_private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        symmetric_key = rsa_cipher.decrypt(encrypted_key)

        aes_cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        plaintext = aes_cipher.decrypt(ciphertext)
        return plaintext.decode()
    except (ValueError, TypeError, Exception) as e:
        raise ValueError("Decryption failed. The input data may be corrupted or tampered.") from e
##############################################################################################################


#Main Program 
if __name__ == "__main__":
    print("Cryptographic Toolkit, choose one of the solutions below: ")
    print("1. Data confidentiality assurance by symmetric encryption")
    print("2. Data confidentiality assurance by hybrid encryption (digital envelope).")
    print("3. Message Authentication assurance. ")
    choice = input("Enter your choice: ")

    if choice == '1':
        print("\nSelect action:")
        print("1. Encrypt")
        print("2. Decrypt")
        cryptomode = input("Enter your choice: ")
##############################################################################################################
        if cryptomode == '1':
            plaintext = input("Enter plaintext: ")
            key = input("Enter 8-byte key: ").encode()
            #Key Size: DES requires a key of 64 bits (8 bytes) for encryption and decryption.
            #However, only 56 bits of the key are used for encryption; 
            #the remaining 8 bits are used for parity (error-checking purposes).
            if len(key) != 8:
                print("Key must be exactly 8 bytes long.")
                exit()

            print("\nEncrypting using ECB mode...")
            encrypted_ecb = encrypt_des(plaintext, key, 'ECB')
            print(f"ECB Ciphertext: {encrypted_ecb.hex()}")

            print("\nSelect another DES mode (CBC, CFB, OFB):")
            mode = input("Enter mode: ").upper()

            if mode not in ['CBC', 'CFB', 'OFB']:
                print("Invalid mode selected. Exiting.")
                exit()

            iv_or_nonce = os.urandom(8)
            print(f"Generated IV/Nonce: {iv_or_nonce.hex()}")

            print(f"\nEncrypting using {mode} mode...")
            encrypted_text = encrypt_des(plaintext, key, mode, iv_or_nonce)
            print(f"{mode} Ciphertext: {encrypted_text.hex()}")

        elif cryptomode == '2':
            ciphertext = bytes.fromhex(input("Enter ciphertext (hex): "))
            key = input("Enter 8-byte key: ").encode()

            if len(key) != 8:
                print("Key must be exactly 8 bytes long.")
                exit()

            print("\nSelect DES mode (ECB, CBC, CFB, OFB):")
            mode = input("Enter mode: ").upper()

            iv_or_nonce = bytes.fromhex(input("Enter IV/Nonce (hex): ")) if mode != 'ECB' else None
            decrypted_text = decrypt_des(ciphertext, key, mode, iv_or_nonce)
            print(f"Decrypted Text: {decrypted_text}")
##############################################################################################################
    elif choice == '2':
        print("1. Generate Key Pair")
        print("2. Encrypt")
        print("3. Decrypt")
        cryptomode = input("Enter your choice (1/2/3): ")

        if cryptomode == '1':
            generate_key_pair()
        elif cryptomode == '2':
            plaintext = input("Enter plaintext to encrypt: ")
            receiver_public_key_path = input("Enter the path to the receiver's public key file: ")
            with open(receiver_public_key_path, "r") as f:
                receiver_public_key = f.read()
            encrypted_data = hybrid_encrypt(plaintext, receiver_public_key)
            print("Encrypted Data:")
            print(f"Encrypted Key: {encrypted_data['encrypted_key']}")
            print(f"Nonce: {encrypted_data['nonce']}")
            print(f"Ciphertext: {encrypted_data['ciphertext']}")
        elif cryptomode == '3':
            encrypted_key_b64 = input("Enter the encrypted key: ")
            nonce_b64 = input("Enter the nonce: ")
            ciphertext_b64 = input("Enter the ciphertext: ")
            receiver_private_key_path = input("Enter the path to the receiver's private key file: ")
            with open(receiver_private_key_path, "r") as f:
                receiver_private_key = f.read()
            decrypted_text = hybrid_decrypt(encrypted_key_b64, nonce_b64, ciphertext_b64, receiver_private_key)
            print("Decrypted Text:", decrypted_text)
##############################################################################################################
    elif choice == '3':
        print("1. Generate MAC")
        print("2. Verify MAC")
        mac_choice = input("Enter your choice (1/2): ")
        if mac_choice == '1':
            input_message = input("Enter a message: ")
            current_timestamp = int(time.time())
            authenticated_message = generate_mac(input_message, current_timestamp)
            print(f"Authenticated Message with MAC: {authenticated_message}")
        elif mac_choice == '2':
            received_message_with_mac = input("Enter the message with MAC: ")
            verification_result = verify_mac(received_message_with_mac)
            print(verification_result)
##############################################################################################################

