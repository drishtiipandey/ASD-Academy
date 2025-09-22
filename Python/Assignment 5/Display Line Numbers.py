#Q1. Display Line Numbers
#Sol:

# Open the file in read mode
with open("data.txt", "r") as file:
    # Loop through each line with enumerate for line numbers
    for line_number, line in enumerate(file, start=1):
        # Strip newline characters and print with line number
        print(f"{line_number}: {line.strip()}")
