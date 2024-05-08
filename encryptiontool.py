import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def encrypt(plaintext, key):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create an AES cipher object with a 256-bit key and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Generate a padding object and pad the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext using the AES cipher in CBC mode
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Concatenate the IV and ciphertext and return the result as a bytes object
    return iv + ciphertext

def decrypt(ciphertext, key):
    # Extract the IV from the ciphertext
    iv = ciphertext[:16]

    # Create an AES cipher object with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Decrypt the ciphertext using the AES cipher in CBC mode
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Unpad the plaintext using the same padding object used to pad the plaintext during encryption
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Return the plaintext as a bytes object
    return plaintext


    
def main():     
    menu = int(input("1.Encrypt file\n2.Decrypt file\nEnter task: "))

    if menu == 1:
        key = secrets.token_bytes(32)  # Generate a random 256-bit key
        with open("key.txt", "wb") as file4:
            #key1 = str(key)
            #key1 = key1[1::]
            file4.write(key)
        #plaintext = input("Enter Plain Text: ")
        
        with open("test.txt", "r") as file1:
            file_content = file1.read()
        bytestext = bytes(file_content, "ascii")
        #print(bytestext)
        ciphertext = encrypt(bytestext, key)
        with open("Ciphertext.txt", "wb") as file2:
            #ciphertext1 = str(ciphertext)
            #ciphertext1 = ciphertext1[1::]
            file2.write(ciphertext)
        #print(f'Ciphertext: {ciphertext}')
        print("\n \nText Encrypted")
        ###### after text in encrypted delete the unencrypted file i.e in this case test.txt
        
    elif menu == 2: 
        with open("key.txt", "rb") as file4:
            file_content = file4.read()
       # key = bytes(file_content, "ascii")
        key = file_content
        #print("key: ", key)
        ##### the key should not be saved on memory it should be sent someplace
        
        
        with open("Ciphertext.txt", "rb") as file3:
            filecontent = file3.read()
            #print("filecontent:" ,filecontent)
            ciphertext = filecontent
        #ciphertext = bytes(ciphertext, "ascii")
        #print("ciphertext: ", ciphertext)
        
        
        
        decrypted_plaintext = decrypt(ciphertext, key)
        with open("Ciphertext.txt", "wb") as file5:
            #ciphertext1 = str(ciphertext)
            #ciphertext1 = ciphertext1[1::]
            file5.write(decrypted_plaintext)
        print("\n \nText Decrypted")
        #print(f'Decrypted plaintext: {decrypted_plaintext}')

    else:
        print("Try again")

main()

#
#write a code to open a file and encrypt it
#write the code to save the encrypted text in a file and then the encryption key into another file
# then also write a code to save the decrypted text in a new file when encryption key is provided.





##This implementation uses the AES encryption algorithm in CBC mode with a 256-bit key, as well as PKCS#7 padding for 
# message block alignment. To enhance the security of the encryption scheme, a random initialization vector (IV) is 
# generated for each encryption operation, and a secure random number generator is used to generate a random key. Note that 
# the use of a secure random number generator and proper key management practices are essential for strong encryption.

#Again, it is important to note that this implementation alone may not be sufficient to provide strong security for 
# real-world applications. Therefore, it is highly recommended to consult with a security expert or do extensive research 
# on encryption best practices before deploying an encryption scheme in a real-world application.