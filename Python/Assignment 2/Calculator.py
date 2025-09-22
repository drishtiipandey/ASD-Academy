4.Simple Calculator

# Simple calculator program 

num1 = int(input("Enter first number: "))
num2 = int(input("Enter second number: "))
operator = input("Enter operator (+, -, *, /): ")

#operation based on input
if operator == '+':
    print("Result:", num1 + num2)
elif operator == '-':
    print("Result:", num1 - num2)
elif operator == '*':
    print("Result:", num1 * num2)
elif operator == '/':
    if num2 != 0:
        print("Result:", num1 // num2) 
    else:
        print("Cannot divide by zero")
else:
    print("Invalid operator")

#Output
Enter first number: 20
Enter second number: 18
Enter operator (+, -, *, /): *
Result: 360    
