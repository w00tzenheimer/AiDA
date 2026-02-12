import os
import subprocess
import sys
import platform

def run_command(command, cwd=None):
    print(f"Running: {command}")
    try:
        subprocess.check_call(command, shell=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        sys.exit(1)

def main():
    root_dir = os.getcwd()
    ida_sdk_dir = os.path.join(root_dir, ".ida_sdk")
    
    # 1. Setup IDA SDK
    if not os.path.exists(ida_sdk_dir):
        print("Cloning IDA SDK...")
        run_command(f"git clone --depth 1 https://github.com/HexRaysSA/ida-sdk.git {ida_sdk_dir}")
    else:
        print("IDA SDK directory already exists.")

    # Detect proper IDASDK path (handle GitHub structure)
    final_sdk_path = ida_sdk_dir
    if os.path.exists(os.path.join(ida_sdk_dir, "src", "include", "pro.h")):
        print("Detected GitHub SDK structure (src/include).")
        final_sdk_path = os.path.join(ida_sdk_dir, "src")
    elif os.path.exists(os.path.join(ida_sdk_dir, "include", "pro.h")):
        print("Detected Standard SDK structure.")
    else:
        print("Warning: Could not detect pro.h in SDK directory.")

    # 2. Setup Env Vars for GitHub Actions
    if "GITHUB_ENV" in os.environ:
        print(f"Setting IDASDK={final_sdk_path} in GITHUB_ENV")
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"IDASDK={final_sdk_path}\n")
    
    # 3. Setup ida-cmake
    ida_cmake_dir = os.path.join(root_dir, ".ida_cmake")
    if not os.path.exists(ida_cmake_dir):
        print("Cloning ida-cmake...")
        run_command(f"git clone --depth 1 https://github.com/allthingsida/ida-cmake.git {ida_cmake_dir}")
    
    if "GITHUB_ENV" in os.environ:
         with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"IDA_CMAKE_DIR={ida_cmake_dir}\n")

if __name__ == "__main__":
    main()
