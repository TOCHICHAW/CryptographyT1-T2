from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def get_private_key_from_file(file_path):
    with open(file_path, "rb") as file:
        key_bytes = file.read()
        return serialization.load_pem_private_key(key_bytes, password=None)

def get_public_key_from_file(file_path):
    with open(file_path, "rb") as file:
        key_bytes = file.read()
        return serialization.load_pem_public_key(key_bytes)

def decrypt_message_with_private_key(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def check_signature_with_public_key(public_key, decrypted_message, signature):
    try:
        public_key.verify(
            signature,
            decrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Identifiers for participants
sender_name = "alice"
receiver_name = "bob"

# Retrieve keys for the sender and receiver
receiver_private_key = get_private_key_from_file(f"{receiver_name}_rsa_private_key.pem")
sender_public_key = get_public_key_from_file(f"{sender_name}_rsa_public_key.pem")

# Load the encrypted message
with open("encrypted_message.enc", "rb") as encrypted_file:
    encrypted_msg = encrypted_file.read()

# Decrypt the message with the receiver's private key
decrypted_msg = decrypt_message_with_private_key(receiver_private_key, encrypted_msg)

# Load the sender's signature
with open(f"{sender_name}_message_signature.sig", "rb") as signature_file:
    sender_signature = signature_file.read()

# Verify the sender's signature
is_signature_valid = check_signature_with_public_key(sender_public_key, decrypted_msg, sender_signature)
print(f"Signature validity: {is_signature_valid}")

# Save the decrypted message
with open("unsealed_message.dec", "wb") as output_file:
    output_file.write(decrypted_msg)
    print('Decrypted message saved')
