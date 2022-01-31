import os
import time
import typing

import psrp


def test_winrm() -> typing.Tuple[str, str, int]:
    connection = psrp.WSManInfo(
        server=os.environ["PYPSRP_SERVER"],
        username=os.environ["PYPSRP_USERNAME"],
        password=os.environ["PYPSRP_PASSWORD"],
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        return ps.add_script("whoami.exe").invoke()[0]


def main() -> None:
    attempt = 1
    total_attempts = 5

    while True:
        print(f"Starting WinRM attempt {attempt}")

        try:
            out = test_winrm()

        except Exception as e:
            print(f"Connection attempt {attempt} failed: {e!s}")

            if attempt == total_attempts:
                raise Exception(f"Exhausted {total_attempts} checking WinRM connection")

            print("Sleeping for 5 seconds before next attempt")
            attempt += 1
            time.sleep(5)

        else:
            print(f"Connection successful\n{out}")
            break


if __name__ == "__main__":
    main()
