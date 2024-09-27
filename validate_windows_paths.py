import os
import re

# Regex pattern for validating Windows file paths
path_pattern = re.compile(
    r'^(?:[a-zA-Z]:|\\\\[a-zA-Z0-9._-]+(\\[a-zA-Z0-9._-]+)*|\\?[^\\/:*?"<>|]+)\\?(?:[^\\/:*?"<>|\r\n]*\\)*[^\\/:*?"<>|\r\n]*$'
)

def is_valid_path(path):
    #todo: open file with list of paths to check against
    return path_pattern.match(path) is not None

def walk_filesystem(root):
    
    for dirpath, dirnames, filenames in os.walk(root):
        # Validate the directory path
        if is_valid_path(dirpath):
            print(f"Valid directory: {dirpath}")
        else:
            print(f"Invalid directory: {dirpath}")

        # Validate each file path
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if is_valid_path(file_path):
                print(f"Valid file: {file_path}")
            else:
                print(f"Invalid file: {file_path}")

if __name__ == "__main__":
    # Start walking the filesystem from the root of the C: drive
    root_directory = "C:\\"
    
    try:
        walk_filesystem(root_directory)
    except Exception as e:
        print(f"An error occurred: {e}")
