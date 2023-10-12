#!/usr/bin/env python

def fibonacci(n):
    """Return the nth fibonacci number."""
    if n <= 1:
        return n
    else:
        return fibonacci(n-1) + fibonacci(n-2)
    
def lucas(n):
    """Return the nth lucas number."""
    if n == 0:
        return 2
    elif n == 1:
        return 1
    else:
        return lucas(n-1) + lucas(n-2)

def sum_series(n, first=0, second=1):
    """Return the nth value of a series."""
    if n == 0:
        return first
    elif n == 1:
        return second
    else:
        return sum_series(n-1, first, second) + sum_series(n-2, first, second)


if __name__ == "__main__":
    print(f"fibonacci(5) {fibonacci(5)}")
    print(f"lucas(5) {lucas(5)}")
    print(f"sum_series(5,3,2) {sum_series(5, 3, 2)}")
    assert fibonacci(5) == 5
    assert lucas(5) == 11
    assert sum_series(5) == 5
    assert sum_series(5, 2, 1) == 11
    assert sum_series(5, 3, 2) == 18
    print("Tests passed.")
