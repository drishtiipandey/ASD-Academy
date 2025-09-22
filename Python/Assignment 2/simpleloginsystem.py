# Program to check username and password

username = input("Enter username: ")  # Take username
password = input("Enter password: ")  # Take password

# Check username first
if username == "admin":
    # Check password inside username condition
    if password == "1234":
        print("Login successful")
    else:
        print("Incorrect password")
else:
    print("Incorrect username")
