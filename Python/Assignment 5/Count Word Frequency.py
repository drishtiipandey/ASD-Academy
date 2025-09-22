#Q2. Count Word Frequency
import string  # For removing punctuation
# Open the file
with open("data.txt", "r") as file:
    text = file.read()
# Convert text to lowercase
text = text.lower()
# Remove punctuation
text = text.translate(str.maketrans("", "", string.punctuation))
# Split into words
words = text.split()
# Create dictionary to store word counts
word_count = {}

for word in words:
    word_count[word] = word_count.get(word, 0) + 1
# Display the result
for word, count in word_count.items():
    print(f"{word}: {count}")
