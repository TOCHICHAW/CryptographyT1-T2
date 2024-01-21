from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_keys_for_individual(individual_name):
    # Initialize RSA private key
    individual_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Initialize RSA public key
    individual_public_key = individual_private_key.public_key()

    # Define file paths for keys
    file_path_private = f"{individual_name}_rsa_private_key.pem"
    file_path_public = f"{individual_name}_rsa_public_key.pem"

    # Store private key in its file
    with open(file_path_private, "wb") as file_private:
        file_private.write(
            individual_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Store public key in its file
    with open(file_path_public, "wb") as file_public:
        file_public.write(
            individual_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        print(f"RSA keys generated for {individual_name}")

    return individual_public_key, individual_private_key

# Generate RSA key pairs for two individuals
generate_keys_for_individual("alice")
generate_keys_for_individual("bob")