"""Keep Zig's C runtime cache keys stable across temporary SDK installations."""

import os
from pathlib import Path
import shutil
import subprocess


def main():
    zig = shutil.which("zig")
    if zig is None:
        raise RuntimeError("Zig is not on PATH")
    library = Path(zig).resolve().parent / "lib"
    if not library.is_dir():
        raise RuntimeError(f"Zig library directory is missing: {library}")
    stable = Path(os.environ["RUNNER_TEMP"]) / "tinysocks-zig-lib"
    if os.path.lexists(stable):
        if stable.resolve() != library:
            raise RuntimeError(f"Zig library path already has another target: {stable}")
    elif os.name == "nt":
        # A junction needs no symbolic-link privilege and stays on the fast temp drive.
        env = os.environ.copy()
        env["TINYSOCKS_ZIG_LIB_PATH"] = str(stable)
        env["TINYSOCKS_ZIG_LIB_SOURCE"] = str(library)
        subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference = 'Stop'; "
                "New-Item -ItemType Junction -Path $env:TINYSOCKS_ZIG_LIB_PATH "
                "-Target $env:TINYSOCKS_ZIG_LIB_SOURCE | Out-Null",
            ],
            env=env,
            check=True,
        )
    else:
        stable.symlink_to(library, target_is_directory=True)
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        output.write(f"ZIG_LIB_DIR={stable}\n")
    print(f"Zig library: {stable} -> {library}")


if __name__ == "__main__":
    main()
