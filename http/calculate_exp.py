def calculate():
    """
    Takes a mathematical expression from user input and evaluates it.
    This is a security risk because eval() will execute any code given to it.
    """
    print("Vulnerable Calculator")
    expression = input("Enter a mathematical expression (e.g., 5 * 2): ")
    try:
        result = eval(expression)
        print(f"Result: {result}")

    except Exception as e:
        print(f"An error occurred: {e}")
if __name__ == "__main__":
    calculate()
