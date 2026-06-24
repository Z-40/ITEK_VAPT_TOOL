import os
import subprocess
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor

# ==================== CONFIGURATION ====================
# Hardcoded command structure using sqlmap
COMMAND = ["sqlmap", "-r"]
# =======================================================

def process_file(file_path):
    """Worker function executed concurrently for each file."""
    file_name = os.path.basename(file_path)
    
    # Dynamically build the command: ['sqlmap', '-r', 'path/to/file.txt']
    full_command = COMMAND + [file_path]
    output_file_path = f"{file_path}.output.txt"
    
    print(f"🚀 Started: {file_name}")
    
    try:
        result = subprocess.run(
            full_command, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
       
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"--- SUCCESS LOG FOR: {file_name} ---\n")
            f.write(f"COMMAND RUN: {' '.join(full_command)}\n\n")
            if result.stdout.strip():
                f.write(f"--- OUTPUT ---\n{result.stdout}\n")
                
        print(f"✅ Finished: {file_name} -> Saved to {os.path.basename(output_file_path)}")
            
    except subprocess.CalledProcessError as e:
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"--- FAILED LOG FOR: {file_name} ---\n")
            f.write(f"COMMAND RUN: {' '.join(full_command)}\n\n")
            if e.stdout.strip():
                f.write(f"--- OUTPUT ---\n{e.stdout}\n")
            if e.stderr.strip():
                f.write(f"--- ERROR ---\n{e.stderr}\n")
                
        print(f"⚠️ Failed: {file_name} (Error details saved to output file)")
            
    except FileNotFoundError:
        print(f"❌ Error: The command '{COMMAND[0]}' is not recognized or installed.")
        os._exit(1)

def main():
    # Set up command line argument parsing for the directory and workers
    parser = argparse.ArgumentParser(
        description="Run sqlmap concurrently across all request files in a directory."
    )
    
    parser.add_argument("-d", "--dir", required=True, help="Path to the target directory containing your request files")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Maximum concurrent tasks (default: 4)")
    
    args = parser.parse_args()

    target_dir = args.dir
    max_workers = args.workers

    if not os.path.exists(target_dir):
        print(f"Error: The directory '{target_dir}' does not exist.")
        sys.exit(1)

    # Gather all target files, ignoring any .output.txt files
    files = [
        os.path.join(target_dir, f) 
        for f in os.listdir(target_dir) 
        if os.path.isfile(os.path.join(target_dir, f)) and not f.endswith(".output.txt")
    ]

    if not files:
        print(f"No valid files found to process in '{target_dir}'.")
        return

    print(f"Found {len(files)} file(s).")
    print(f"Executing: {' '.join(COMMAND)} <filename>")
    print(f"Processing concurrently (Max threads: {max_workers})...\n")

    # Run the thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_file, files)

    print("\n All files have been processed independently!")

if __name__ == "__main__":
    main()
    