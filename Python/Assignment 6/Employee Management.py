# Base class
class Employee:
    def __init__(self, name, employee_id, department):
        self.name = name
        self.employee_id = employee_id
        self.department = department

    def display_details(self):
        print(f"Name: {self.name}")
        print(f"Employee ID: {self.employee_id}")
        print(f"Department: {self.department}")


# Derived class: Manager
class Manager(Employee):
    def __init__(self, name, employee_id, department, team_size):
        super().__init__(name, employee_id, department)  # Call parent constructor
        self.team_size = team_size

    def display_details(self):
        super().display_details()  # Call parent method
        print(f"Team Size: {self.team_size}")


# Derived class: Developer
class Developer(Employee):
    def __init__(self, name, employee_id, department, programming_language):
        super().__init__(name, employee_id, department)
        self.programming_language = programming_language

    def display_details(self):
        super().display_details()
        print(f"Programming Language: {self.programming_language}")


# ---- Demonstration ----
# Create Manager object
manager1 = Manager("Alice", "M001", "HR", 10)

# Create Developer object
dev1 = Developer("Bob", "D001", "IT", "Python")

# Display details
print("Manager Details:")
manager1.display_details()

print("\nDeveloper Details:")
dev1.display_details()
