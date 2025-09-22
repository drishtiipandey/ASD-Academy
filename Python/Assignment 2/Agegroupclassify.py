6. Age Goup Classifier

# Program to classify age group

age = int(input("Enter age: "))

# Check and print age group
if age < 13:
    print("Child")
elif age <= 19:
    print("Teenager")
elif age <= 59:
    print("Adult")
else:
    print("Senior")

#Output
Enter age: 20
Adult