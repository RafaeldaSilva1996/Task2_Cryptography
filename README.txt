Step by Step to use & understand this Cryptography script successfully :

--->First instal visual studio, alongside all the cryptography modules. 

--->Download & Place the Script Anywhere

The script automatically detects its location (BASE_DIR = os.path.dirname(os.path.abspath(__file__))).

--->Run the Script

This will Generate encrypted and decrypted folders.
Encrypted files will be stored inside EncryptedSecretFolder_Alice or EncryptedSecretFolder_Bob.
Decrypted files will appear in DecryptedSecretFolder_Alice or DecryptedSecretFolder_Bob.

Inside the folders , the encrypted or decrypted files are generated , with the secrete message being passed on 

---> Change Users to Generate New Keys & Folders ( Alice or Bob or any other user name Alice and Bob are the prime standard name examples in cryptography )  selected_user = "Bob" or selected_user = "Alice"

--->If you delete the generated folders (EncryptedSecretFolder_... & DecryptedSecretFolder_...), you can rerun the script to regenerate everything.
The script encrypts the AES key with RSA, ensuring better key security.
HMAC integrity checks prevent data tampering.



--->private_key_alice.pem (Private Key)

This file contains Alice’s private RSA key.
It is only used for decryption and should be kept secret.

This key is not used directly in the script, but if you were to decrypt the encrypted AES key, you would use this.


--->public_key_alice.pem (Public Key)

This file contains Alice’s public RSA key.
It is used to encrypt the AES key so that only Alice (who has the private key) can decrypt it.
This key can be shared because it cannot decrypt—it can only encrypt.
