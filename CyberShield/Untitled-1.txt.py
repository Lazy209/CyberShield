def password_strength_checker(password):
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False
    password_length = len(password) >= 8

    special_chars = "!@#$%^&*()-+"

    for ch in password:
        if ch.islower():
            has_lower = True
        elif ch.isupper():
            has_upper = True
        elif ch.isdigit():
            has_digit = True
        elif ch in special_chars:
            has_special = True

    total_conditions = (
        has_lower + has_upper + has_digit +
        has_special + password_length
    )

    if total_conditions >= 5:
        return "Strong"
    elif total_conditions >= 3:
        return "Medium"
    else:
        return "Weak"


# Main Program
password = input("Enter a password: ")

strength = password_strength_checker(password)
print("Password strength:", strength)

if not any(ch.isupper() for ch in password):
    print("Password must contain at least one uppercase letter.")
elif not any(ch.islower() for ch in password):
    print("Password must contain at least one lowercase letter.")
elif not any(ch.isdigit() for ch in password):
    print("Password must contain at least one digit.")
elif not any(ch in "!@#$%^&*()-+" for ch in password):
    print("Password must contain at least one special character.")
elif len(password) < 8:
    print("Password must be at least 8 characters long.")