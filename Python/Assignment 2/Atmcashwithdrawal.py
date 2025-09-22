8.ATM Cash Withdrawal

# Program for simple ATM withdrawal

balance = 5000  # Initial balance
amount = int(input("Enter amount to withdraw: "))

# Check if amount is multiple of 100
if amount % 100 != 0:
    print("Amount must be multiple of 100")
# Check for sufficient balance
elif amount > balance:
    print("Insufficient balance")
else:
    balance -= amount  # Deduct amount
    print("Withdrawal successful. New balance: Rs.", balance)

#Output
Enter amount to withdraw: 4000
Withdrawal successful. New balance: Rs. 1000
