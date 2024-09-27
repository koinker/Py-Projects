import re
import os
from PyPDF2 import PdfReader
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_pdf_content(pdf_file):
    content = ""
    try:
        pdf_reader = PdfReader(pdf_file)
        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:
                content += page_text + "\n"
    except Exception as e:
        print(f"Error reading {pdf_file}: {e}")
    return content

def find_str(pdf_file, words):
    matches = []
    pdf_content = get_pdf_content(pdf_file)

    print(f"Searching in: {pdf_file}") 
    print(f"Content length: {len(pdf_content)}")  

    if pdf_content:  
        combined_pattern = r"\b(" + re.escape(words[0]) + r")\b"  
        matches = re.findall(combined_pattern, pdf_content, re.IGNORECASE)  

    return (pdf_file, matches)

def walk(main_path, words):
    lst = []
    pdf_files = []


    for d, _, files in os.walk(main_path):
        for file_name in files:
            if file_name.lower().endswith('.pdf'):
                full_path = os.path.join(d, file_name)
                pdf_files.append(full_path)

    results = []
    with ThreadPoolExecutor() as executor:
        future_to_pdf = {executor.submit(find_str, pdf, words): pdf for pdf in pdf_files}
        for future in as_completed(future_to_pdf):
            result = future.result()
            if result[1]:  
                lst.append(result)

    return lst

if __name__ == "__main__":
    word = input("Enter a keyword (or press Enter to finish): ").strip()

    if not word:
        print("No keyword provided. Exiting.")
        exit(1)

    main_path = input("Enter the path to your directory: ").strip()
    
    
    print(f"Checking directory: {main_path}")
    
    if not os.path.isdir(main_path):
        print("Invalid directory path. Exiting.")
        exit(1)

    results = walk(main_path, [word]) 
    
    if results:
        for result in results:
        	print(f"File: {result[0]} contains matching strings: {', '.join(set(result[1]))}")
        	print("Match found!")
    else:
        print("No matches found.")
