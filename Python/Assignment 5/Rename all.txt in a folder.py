#Q5. Rename All .txt Files in a Folder
import os

folder_path = r"C:\Users\drish\Desktop\assignpyth"

# Loop through all files
for filename in os.listdir(folder_path):
    if filename.endswith(".txt") and not filename.startswith("processed_"):
        old_path = os.path.join(folder_path, filename)
        new_path = os.path.join(folder_path, "processed_" + filename)
        os.rename(old_path, new_path)
        print(f"Renamed: {filename} → processed_{filename}")

print("Renaming complete!")
