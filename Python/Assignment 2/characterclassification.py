3.Character Classification

# Program to classify character as vowel, consonant, digit or special character

ch = input("Enter a character: ")  # Take one character input

# Check if alphabet
if ch.isalpha():
    # Check if vowel
    if ch in 'aAeEiIoOuU':
        print("Vowel")
    else:
        print("Consonant")
# Check if digit
elif ch.isdigit():
    print("Digit")
# Else it's special character
else:
    print("Special Character")

#Output
Enter a character: @
Special Character
