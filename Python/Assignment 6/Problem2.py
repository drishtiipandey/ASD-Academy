import math  # For pi value

# Step 1: Create a class Shape
class Shape:
    def area(self):
        print("Area not defined")

# Step 2: Create child class Circle
class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius

    # Step 3: Override area() method
    def area(self):
        result = math.pi * (self.radius ** 2)
        print(f"Area of Circle: {result}")

# Step 2: Create child class Rectangle
class Rectangle(Shape):
    def __init__(self, length, width):
        self.length = length
        self.width = width

    # Step 3: Override area() method
    def area(self):
        result = self.length * self.width
        print(f"Area of Rectangle: {result}")

# Create objects and test
shape1 = Shape()
shape1.area()  # Output: Area not defined

circle1 = Circle(5)
circle1.area()  # Output: Area of Circle: 78.53981633974483

rectangle1 = Rectangle(4, 6)
rectangle1.area()  # Output: Area of Rectangle: 24
