import os
import time
import typing

from pypsrp.client import Client


def test_winrm() -> typing.Tuple[str, str, int]:
    server = os.environ["PYPSRP_SERVER"]
    username = os.environ["PYPSRP_USERNAME"]
    password = os.environ["PYPSRP_PASSWORD"]

    with Client(server, username=username, password=password, cert_validation=False) as c:
        return c.execute_cmd("whoami.exe")


def main() -> None:
    attempt = 1
    total_attempts = 5

    while True:
        print(f"Starting WinRM attempt {attempt}")

        try:
            stdout, stderr, rc = test_winrm()

        except Exception as e:
            print(f"Connection attempt {attempt} failed: {e!s}")

            if attempt == total_attempts:
                raise Exception(f"Exhausted {total_attempts} checking WinRM connection")

            print("Sleeping for 5 seconds before next attempt")
            attempt += 1
            time.sleep(5)

        else:
            print(f"Connection successful\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRC: {rc}")
            break


if __name__ == "__main__":
    main()
