import secrets
import string

def generate_secure_password(length=16):
    if length < 8:
        raise ValueError("Password too short. Please choose at least 8 characters.")

    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation 

    password_characters = [
        secrets.choice(lowercase_letters),
        secrets.choice(uppercase_letters),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    all_characters = lowercase_letters + uppercase_letters + digits + symbols
    remaining_length = length - len(password_characters)

    for _ in range(remaining_length):
        password_characters.append(secrets.choice(all_characters))
    secrets.SystemRandom().shuffle(password_characters)
    final_password = ''.join(password_characters)

    return final_password
if __name__ == "__main__":
    try:
        user_input = input("Enter desired password length (default is 16): ").strip()
        password_length = int(user_input) if user_input else 16
        secure_password = generate_secure_password(password_length)
        print("\nYour password is:")
        print(secure_password)

    except ValueError as error:
        print(f"Error: {error}")
