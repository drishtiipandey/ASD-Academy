# Book class
class Book:
    def __init__(self, title, author, isbn, available=True):
        self.__title = title        # Private attribute
        self.__author = author      # Private attribute
        self.__isbn = isbn          # Private attribute
        self.__available = available # Private attribute

    # Getter methods
    def get_title(self):
        return self.__title

    def get_author(self):
        return self.__author

    def get_isbn(self):
        return self.__isbn

    def is_available(self):
        return self.__available

    # Setter methods for availability
    def set_availability(self, status):
        self.__available = status


# Library class
class Library:
    def __init__(self):
        self.books = []  # List to store Book objects

    def add_book(self, book):
        self.books.append(book)
        print(f"Book '{book.get_title()}' added to library.")

    def remove_book(self, isbn):
        for book in self.books:
            if book.get_isbn() == isbn:
                self.books.remove(book)
                print(f"Book '{book.get_title()}' removed from library.")
                return
        print("Book not found.")

    def lend_book(self, isbn):
        for book in self.books:
            if book.get_isbn() == isbn:
                if book.is_available():
                    book.set_availability(False)
                    print(f"Book '{book.get_title()}' lent successfully.")
                else:
                    print(f"Book '{book.get_title()}' is already lent out.")
                return
        print("Book not found.")

    def return_book(self, isbn):
        for book in self.books:
            if book.get_isbn() == isbn:
                if not book.is_available():
                    book.set_availability(True)
                    print(f"Book '{book.get_title()}' returned successfully.")
                else:
                    print(f"Book '{book.get_title()}' was not lent out.")
                return
        print("Book not found.")

    def list_books(self):
        if not self.books:
            print("Library is empty.")
            return
        print("\nLibrary Collection:")
        for book in self.books:
            status = "Available" if book.is_available() else "Not Available"
            print(f"Title: {book.get_title()} | Author: {book.get_author()} | ISBN: {book.get_isbn()} | Status: {status}")


# ---- Demonstration ----
# Create Book objects
book1 = Book("The Great Gatsby", "F. Scott Fitzgerald", "12345")
book2 = Book("1984", "George Orwell", "67890")
book3 = Book("To Kill a Mockingbird", "Harper Lee", "11121")

# Create Library object
my_library = Library()

# Add books to library
my_library.add_book(book1)
my_library.add_book(book2)
my_library.add_book(book3)

# List all books
my_library.list_books()

# Lend a book
my_library.lend_book("67890")

# Try lending same book again
my_library.lend_book("67890")

# Return a book
my_library.return_book("67890")

# Remove a book
my_library.remove_book("11121")

# List books after operations
my_library.list_books()
