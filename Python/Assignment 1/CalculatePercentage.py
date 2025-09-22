# Taking marks input from the user
English = int(input("Enter marks for English: "))
Physics = int(input("Enter marks for Physics: "))
Chemistry = int(input("Enter marks for Chemistry: "))
Mathematics = int(input("Enter marks for Mathematics: "))
Hindi = int(input("Enter marks for Hindi: "))

# Calculate total marks
total_marks = English + Physics + Chemistry + Mathematics + Hindi

# Calculate percentage
percentage = (total_marks / 500) * 100

# the result
print("Total Marks=",total_marks)
print("Percentage=",percentage)