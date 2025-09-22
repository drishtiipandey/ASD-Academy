nums = [5, 3, 9]
nums.append(7)
nums.remove(3)
nums.sort(reverse=True)
total = sum(nums)
average = total / len(nums)
print("List:", nums)
print("Sum:", total)
print("Average:", average)