#Q3. Remove Blank and Whitespace-Only Lines
# Open the input and output files
with open("data.txt", "r") as infile, open("cleaned_data.txt", "w") as outfile:
    for line in infile:
        # Strip spaces and check if the line is not empty
        if line.strip():
            outfile.write(line)
