import argparse
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad
import binascii

def decrypt_openfirepass(ciphertext, key):
    '''
        Decrypt Openfire password
        
        :params
            ciphertext: Encrypted password
            key: Blowfish key
            
        :exepction
            ValueError: If padding is incorrect
            binascii.Error: If hex is invalid
            
        :return: Decrypted password
    '''
    try:
        ciphertext = binascii.unhexlify(ciphertext) # Convert hex to bytes
    except binascii.Error:
        return "Error: Odd-length string" # Return error if hex is invalid

    sha1_key = SHA1.new(key.encode('utf-8')).digest() # Generate SHA1 key

    iv_size = Blowfish.block_size # IV size
    iv = ciphertext[:iv_size] # Extract IV
    ciphertext = ciphertext[iv_size:] # Extract ciphertext
    
    cipher = Blowfish.new(sha1_key, Blowfish.MODE_CBC, iv) # Create cipher object

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size) # Decrypt and unpad
    except ValueError: 
        return "Error: Padding is incorrect" # Return error if padding is incorrect
    
    return plaintext.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='Decrypt Openfire password')
    parser.add_argument('-p', '--password', required=True, help='Encrypted password')
    parser.add_argument('-k', '--key', required=True, help='Blowfish key')

    args = parser.parse_args()

    decrypted_password = decrypt_openfirepass(args.password, args.key)
    print(f'Decrypted password: {decrypted_password}')

if __name__ == '__main__':
    main()
