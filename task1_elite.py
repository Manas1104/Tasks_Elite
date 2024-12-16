def caesar_cipher(text, shift, mode):
    """
    Encrypts or decrypts a text using the Caesar cipher.

    :param text: The input text to process.
    :param shift: The number of positions to shift the alphabet.
    :param mode: Either 'encrypt' or 'decrypt'.
    :return: The processed text.
    """
    result = ""
    if mode == "decrypt":
        shift = -shift

    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
            result += shifted_char
        else:
            result += char  # Non-alphabetic characters remain unchanged

    return result
# User interaction
def main():
    print("Caesar Cipher Program")
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            message = input("Enter the message to encrypt: ")
            shift = int(input("Enter the shift value: "))
            encrypted_message = caesar_cipher(message, shift, "encrypt")
            print("Encrypted Message:", encrypted_message)
        elif choice == "2":
            message = input("Enter the message to decrypt: ")
            shift = int(input("Enter the shift value: "))
            decrypted_message = caesar_cipher(message, shift, "decrypt")
            print("Decrypted Message:", decrypted_message)
        elif choice == "3":
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
