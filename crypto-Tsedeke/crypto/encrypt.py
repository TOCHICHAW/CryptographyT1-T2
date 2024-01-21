from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def get_private_key(path_to_key):
    with open(path_to_key, "rb") as key_file:
        key_bytes = key_file.read()
        private_key_obj = serialization.load_pem_private_key(
            key_bytes, password=None)
    return private_key_obj

def get_public_key(path_to_key):
    with open(path_to_key, "rb") as key_file:
        key_bytes = key_file.read()
        public_key_obj = serialization.load_pem_public_key(key_bytes)
    return public_key_obj

def generate_signature(private_key, message_data):
    signature = private_key.sign(
        message_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_message(receiver_key, message_data):
    encrypted_data = receiver_key.encrypt(
        message_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('Message encrypted')
    return encrypted_data

# Reading the message to be sent
with open("message.txt", "rb") as msg_file:
    message_to_send = msg_file.read()

# Identifiers for the participants
sender_identifier = "alice"
receiver_identifier = "bob"

# Key retrieval
sender_private_key = get_private_key(f"{sender_identifier}_rsa_private_key.pem")
receiver_public_key = get_public_key(f"{receiver_identifier}_rsa_public_key.pem")

# Encrypting the message for the recipient
encrypted_msg = encrypt_message(receiver_public_key, message_to_send)

# Generating a signature for the message
msg_signature = generate_signature(sender_private_key, message_to_send)

# Storing the encrypted message and its signature
with open("encrypted_message.enc", "wb") as encrypted_file:
    encrypted_file.write(encrypted_msg)

with open(f"{sender_identifier}_message_signature.sig", "wb") as signature_file:
    signature_file.write(msg_signature)

print("Encrypted message and signature stored.")
