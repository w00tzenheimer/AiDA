import subprocess
import sys
import argparse
import shutil
from pathlib import Path
import os # Still needed for environ

"""
Build Helper Script for AiDA
============================

This script handles environment setup and artifact management for the AiDA project,
designed to work across Windows, Linux, and macOS in both CI (GitHub Actions)
and local development environments.

Key functions:
1. `setup`: Clones dependencies (IDA SDK, ida-cmake) and configures environment variables.
2. `copy-artifact`: Locates the built plugin binary and copies it to a centralized `artifacts/` directory.
"""

def run_command(command, cwd=None):
    """
    Executes a shell command.

    Args:
        command (str): The command to run.
        cwd (str, optional): The current working directory for the command.
    """
    print(f"Running: {command}")
    try:
        subprocess.check_call(command, shell=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        sys.exit(1)

def setup_env():
    """
    Sets up the build environment by cloning necessary dependencies.

    Operations:
    - Clones `ida-sdk` (Hex-Rays GitHub mirror) if not present.
    - Clones `ida-cmake` build system if not present.
    - Detects the SDK structure (standard vs. GitHub mirror).
    - Exports `IDASDK` and `IDA_CMAKE_DIR` to $GITHUB_ENV if running in CI.
    """
    root_dir = Path.cwd()
    ida_sdk_dir = root_dir / ".ida_sdk"
    
    # 1. Setup IDA SDK
    if not ida_sdk_dir.exists():
        print("Cloning IDA SDK...")
        run_command(f"git clone --depth 1 https://github.com/HexRaysSA/ida-sdk.git {ida_sdk_dir}")
    else:
        print("IDA SDK directory already exists.")

    # Detect proper IDASDK path (handle GitHub structure)
    final_sdk_path = ida_sdk_dir
    if (ida_sdk_dir / "src" / "include" / "pro.h").exists():
        print("Detected GitHub SDK structure (src/include).")
        final_sdk_path = ida_sdk_dir / "src"
    elif (ida_sdk_dir / "include" / "pro.h").exists():
        print("Detected Standard SDK structure.")
    else:
        print("Warning: Could not detect pro.h in SDK directory.")

    # 2. Setup Env Vars for GitHub Actions
    if "GITHUB_ENV" in os.environ:
        print(f"Setting IDASDK={final_sdk_path} in GITHUB_ENV")
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"IDASDK={final_sdk_path}\n")
    
    # 3. Setup ida-cmake
    ida_cmake_dir = root_dir / ".ida_cmake"
    if not ida_cmake_dir.exists():
        print("Cloning ida-cmake...")
        run_command(f"git clone --depth 1 https://github.com/allthingsida/ida-cmake.git {ida_cmake_dir}")
    
    if "GITHUB_ENV" in os.environ:
         with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"IDA_CMAKE_DIR={ida_cmake_dir}\n")

def copy_artifact(extension, search_dir=None):
    """
    Locates and copies the built plugin artifact to the artifacts directory.

    Args:
        extension (str): The file extension of the artifact (e.g., 'dll', 'so', 'dylib').
        search_dir (str, optional): Specific directory to search in. If not provided,
                                    defaults to standard build output locations.
    
    Search Logic:
    1. If `search_dir` is provided, searches only there.
    2. Otherwise, searches:
       - ./build
       - $IDABIN/plugins (if IDABIN set)
       - $IDASDK/bin/plugins and $IDASDK/plugins (if IDASDK set)
    """
    root_dir = Path.cwd()
    artifacts_dir = root_dir / "artifacts"
    
    filename = f"AiDA.{extension}"
    print(f"Looking for {filename}...")
    
    # Create artifacts directory if it doesn't exist
    artifacts_dir.mkdir(exist_ok=True)
    
    search_dirs = []
    
    if search_dir:
        search_dirs.append(Path(search_dir))
    else:
        # Default search locations
        search_dirs.append(root_dir / "build")
        
        # Check IDABIN environment variable
        if "IDABIN" in os.environ:
             search_dirs.append(Path(os.environ["IDABIN"]) / "plugins")

        # Check IDASDK environment variable
        if "IDASDK" in os.environ:
            idasdk_path = Path(os.environ["IDASDK"])
            search_dirs.append(idasdk_path / "bin" / "plugins")
            search_dirs.append(idasdk_path / "plugins")

    found = False
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
            
        print(f"Searching in {search_dir}...")
        for path in search_dir.rglob(filename):
            print(f"Found artifact: {path}")
            shutil.copy2(path, artifacts_dir / filename)
            print(f"Copied to: {artifacts_dir / filename}")
            found = True
            
            # On Windows, also try to copy bundled OpenSSL DLLs from the same directory
            if extension == "dll":
                print("Checking for bundled OpenSSL DLLs...")
                for dll in path.parent.glob("*.dll"):
                    if dll.name.lower().startswith(("libssl", "libcrypto")):
                        shutil.copy2(dll, artifacts_dir / dll.name)
                        print(f"Copied bundled DLL: {dll.name}")
            break
        
        if found:
            break
        
    if not found:
        print(f"Error: Could not find {filename} in any of: {[str(d) for d in search_dirs]}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Build helper script")
    subparsers = parser.add_subparsers(dest='command')
    
    # Setup command
    subparsers.add_parser('setup', help='Setup build environment')
    
    # Copy artifact command
    copy_parser = subparsers.add_parser('copy-artifact', help='Copy build artifact')
    copy_parser.add_argument('--extension', required=True, help='Plugin extension (dll, so, dylib)')
    copy_parser.add_argument('--search-dir', help='Explicit directory to search for artifact')
    
    args = parser.parse_args()
    
    if args.command == 'setup' or args.command is None:
        setup_env()
    elif args.command == 'copy-artifact':
        copy_artifact(args.extension, args.search_dir)


if __name__ == "__main__":
    main()
