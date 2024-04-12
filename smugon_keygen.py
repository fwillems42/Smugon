import os.path
import sys


def main():
    assert len(sys.argv) > 2, f'Usage: python {sys.argv[0]} <SIZE> <FILE>'

    size = 0
    try:
        size = int(sys.argv[1])
        file = sys.argv[2]

        with open(file, 'wb') as f:
            f.write(os.urandom(size))

    except TypeError as e:
        print(f"Invalid size provided: {size}")
    except Exception as e:
        print(f"Unknown error of type {e}")


if __name__ == '__main__':
    main()
