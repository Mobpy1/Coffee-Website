import csv
from cryptography.fernet import Fernet


# Load the encryption key
def load_key(key_file="key.key"):
    with open(key_file, "rb") as f:
        return f.read()


# Encrypt a password
def encrypt_password(plain_password, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plain_password.encode())
    return encrypted


# Encrypt passwords in the CSV file
def encrypt_csv(input_file, output_file, key):
    key = load_key(key)  # Load encryption key
    with open(input_file, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)

    # Ensure the CSV has headers, and the password is in the correct column
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # If the file has a header, write it first
        writer.writerow(rows[0])  # Assuming the first row is the header

        for row in rows[1:]:
            if len(row) >= 3:  # Ensure the row has at least 3 columns
                row[2] = encrypt_password(row[2], key)  # Encrypt the password (assuming password is in column 2)
            writer.writerow(row)
    print(f"Encrypted CSV saved as '{output_file}'.")


# Example usage
if __name__ == "__main__":
    key_file = "key.key"  # The key file
    input_csv = "users.csv"  # The input CSV file (before encryption)
    encrypted_csv = "encrypted_passwords.csv"  # The output CSV file (after encryption)

    encrypt_csv(input_csv, encrypted_csv, key_file)
