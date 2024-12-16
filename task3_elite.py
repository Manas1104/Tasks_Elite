import re

def assess_password_strength(password):
    """
    Assess the strength of a password based on multiple criteria.

    :param password: The password string to assess.
    :return: A string indicating the password strength and feedback.
    """
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    strength_score = sum(
        [
            length_criteria,
            uppercase_criteria,
            lowercase_criteria,
            number_criteria,
            special_char_criteria
        ]
    )

    if strength_score == 5:
        feedback = "Strong password!"
    elif 3 <= strength_score < 5:
        feedback = "Moderate password. Consider adding more complexity."
    else:
        feedback = "Weak password. Add more characters, numbers, and special symbols."

    return feedback

def main():
    print("Password Strength Assessment Tool")
    while True:
        print("\nChoose an option:")
        print("1. Assess password strength")
        print("2. Exit")
        choice = input("Enter your choice (1/2): ")

        if choice == "1":
            password = input("Enter a password to assess: ")
            feedback = assess_password_strength(password)
            print(f"Password Strength Feedback: {feedback}")
        elif choice == "2":
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
