# Sum Until Limit (while + break)
total = 0
while True:
    num = int(input("Enter a number: "))
    total += num
    if total > 100:
        break
print("Sum exceeded 100.")