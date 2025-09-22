#Login Attempt

correct = "python123"
attempt = 0
while attempt < 3:
 pwd = input("Enter password: ")
 if pwd == correct:
  print("Login Successful")
#  break
#  attempt += 1
else:
   print("Account Locked")