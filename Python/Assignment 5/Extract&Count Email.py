#Q4. Extract and Count Email Addresses
import re  # For regular expressions
# Read the file
with open("emails.txt", "r") as file:
    text = file.read()
# Regular expression to match email addresses
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
# Find all emails
emails = re.findall(email_pattern, text)
# Remove duplicates by converting to a set
unique_emails = sorted(set(emails))  # Sorted alphabetically
# Display results
print("Unique Email Addresses:")
for email in unique_emails:
    print(email)

print(f"\nTotal unique emails found: {len(unique_emails)}")
