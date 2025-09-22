1.Leap year Checker

# Program to check leap year

year = int(input("Enter a year: "))  # Take year input

# Check leap year conditions
if (year % 4 == 0):
    if (year % 100 == 0):
        if (year % 400 == 0):
            print("Leap year")
        else:
            print("Not a leap year")
    else:
        print("Leap year")
else:
    print("Not a leap year")

#Output
Enter a year: 2015
Not a leap year
