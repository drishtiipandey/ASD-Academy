skip = int(input("Enter a number to skip (120): "))
for i in range(1, 21):
 if i == skip:
  continue
 print(i)