from PIL import Image
import numpy as np

def encrypt_image(input_path, output_path, key):
    """
    Encrypts an image by adding a key to each pixel value.

    :param input_path: Path to the input image.
    :param output_path: Path to save the encrypted image.
    :param key: Integer key used for encryption.
    """
    image = Image.open(input_path)
    image_array = np.array(image, dtype=np.uint8)

    # Encrypt by adding the key and ensuring the result is within bounds
    encrypted_array = (image_array + key).astype(np.uint8)
    encrypted_image = Image.fromarray(encrypted_array)
    encrypted_image.save(output_path)
    print(f"Image encrypted and saved to {output_path}")

def decrypt_image(input_path, output_path, key):
    """
    Decrypts an image by subtracting a key from each pixel value.

    :param input_path: Path to the encrypted image.
    :param output_path: Path to save the decrypted image.
    :param key: Integer key used for decryption.
    """
    image = Image.open(input_path)
    image_array = np.array(image, dtype=np.uint8)

    # Decrypt by subtracting the key and ensuring the result is within bounds
    decrypted_array = (image_array - key).astype(np.uint8)
    decrypted_image = Image.fromarray(decrypted_array)
    decrypted_image.save(output_path)
    print(f"Image decrypted and saved to {output_path}")

def main():
    print("Simple Image Encryption Tool")
    while True:
        print("\nChoose an option:")
        print("1. Encrypt an image")
        print("2. Decrypt an image")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            input_path = input("Enter the path to the input image: ")
            output_path = input("Enter the path to save the encrypted image: ")
            key = int(input("Enter the encryption key (integer): "))
            encrypt_image(input_path, output_path, key)
        elif choice == "2":
            input_path = input("Enter the path to the encrypted image: ")
            output_path = input("Enter the path to save the decrypted image: ")
            key = int(input("Enter the decryption key (integer): "))
            decrypt_image(input_path, output_path, key)
        elif choice == "3":
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
