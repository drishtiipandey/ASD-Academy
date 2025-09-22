#Skip a character

text = input("Enter a string:")
for ch in text:
    if ch == 'a':
        continue
    print(ch)