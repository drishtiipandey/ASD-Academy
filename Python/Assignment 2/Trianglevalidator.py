# Program to check if 3 sides form a triangle

a = int(input("Enter side A: "))
b = int(input("Enter side B: "))
c = int(input("Enter side C: "))

# Check triangle validity using triangle inequality theorem
if a + b > c and b + c > a and c + a > b:
    # Check type of triangle
    if a == b == c:
        print("Equilateral triangle")
    elif a == b or b == c or c == a:
        print("Isosceles triangle")
    else:
        print("Scalene triangle")
else:
    print("Not a valid triangle")
