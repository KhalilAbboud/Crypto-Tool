import hashlib
import base64
from cryptography.fernet import Fernet  # type: ignore

# Stored values
stored_key = None
stored_encrypted = None


def generate_key_from_password(password: str):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def menu():
    print("\nChoose an option")
    print("-------------------------")
    print("1 - Encrypt text")
    print("2 - Decrypt text")
    print("3 - Compute SHA-256")
    print("4 - Compare two hashes")
    print("5 - Quit")
    return input("Choice: ")


def encrypt():
    global stored_key, stored_encrypted

    text = input("Enter text to encrypt: ")
    password = input("Enter password: ")

    key = generate_key_from_password(password)
    f = Fernet(key)

    encrypted = f.encrypt(text.encode())

    stored_key = key
    stored_encrypted = encrypted

    print("Encrypted:", encrypted.decode())


def decrypt():
    global stored_key, stored_encrypted

    choice = input("Use stored values? (y/n): ")

    if choice.lower() == 'y' and stored_encrypted:
        key = stored_key
        encrypted = stored_encrypted
    else:
        encrypted = input("Enter encrypted value: ").encode()
        password = input("Enter password: ")
        key = generate_key_from_password(password)

    try:
        f = Fernet(key)
        decrypted = f.decrypt(encrypted)
        print("Decrypted:", decrypted.decode())
    except:
        print("Decryption failed (wrong key or data)")


def compute_sha256():
    text = input("Enter text: ")
    hash_value = hashlib.sha256(text.encode()).hexdigest()
    print("SHA-256:", hash_value)


def compare_hashes():
    hash1 = input("Enter first hash: ")
    hash2 = input("Enter second hash: ")

    if hash1 == hash2:
        print("Hashes match (no modification)")
    else:
        print("Hashes do NOT match (data modified)")


def main():
    while True:
        choice = menu()

        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '3':
            compute_sha256()
        elif choice == '4':
            compare_hashes()
        elif choice == '5':
            print("Bye")
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()