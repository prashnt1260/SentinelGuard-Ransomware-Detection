import hashlib
import os
import pefile
import numpy as np
from collections import Counter
import re

def calculate_entropy(data):
    """Calculate the Shannon entropy of a given byte string."""
    if not data:
        return 0.0
    
    byte_counts = Counter(data)
    probabilities = [count / len(data) for count in byte_counts.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    return entropy

def extract_pe_features(filepath):
    """
    Extracts various features from a Portable Executable (PE) file.
    Returns a dictionary of features. Returns None if not a valid PE file or error occurs.
    """
    features = {
        'file_size': 0,
        'entropy': 0.0,
        'num_sections': 0,
        'entry_point': 0,
        'major_linker_version': 0,
        'minor_linker_version': 0,
        'image_base': 0,
        'number_of_rva_and_sizes': 0,
        'characteristics_dll': 0,
        'characteristics_executable_image': 0,
        'characteristics_32bit_machine': 0,
        'timestamp': 0,
        'has_debug_info': 0,
        'num_imported_dlls': 0,
        'num_imported_functions': 0,
        'has_resource_section': 0,
        'has_reloc_section': 0,
        'is_packed_upx': 0, # Simple check for UPX string
        # You can add more specific feature counts for certain suspicious APIs
        'VirtualAlloc_import': 0,
        'CreateRemoteThread_import': 0,
        'WriteProcessMemory_import': 0,
        'NtCreateSection_import': 0,
        'RegSetValueEx_import': 0,
        'CryptEncrypt_import': 0,
        'SetWindowsHookEx_import': 0,
        'LoadLibrary_import': 0,
        'GetProcAddress_import': 0,
    }

    try:
        file_content = open(filepath, 'rb').read()
        features['file_size'] = len(file_content)
        features['entropy'] = calculate_entropy(file_content)

        pe = pefile.PE(filepath)

        # DOS Header
        # No significant features directly taken from DOS header for this scope

        # COFF File Header
        features['num_sections'] = pe.FILE_HEADER.NumberOfSections
        features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['characteristics_dll'] = 1 if pe.FILE_HEADER.IMAGE_FILE_DLL else 0
        features['characteristics_executable_image'] = 1 if pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE else 0
        features['characteristics_32bit_machine'] = 1 if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE else 0


        # Optional Header
        features['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['major_linker_version'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['minor_linker_version'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['image_base'] = pe.OPTIONAL_HEADER.ImageBase
        features['number_of_rva_and_sizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # Data Directories
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            features['has_debug_info'] = 1
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            features['has_resource_section'] = 1
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            features['has_reloc_section'] = 1

        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['num_imported_dlls'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    features['num_imported_functions'] += 1
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else ''
                    
                    # Specific API calls that might indicate suspicious activity
                    if 'VirtualAlloc' in func_name: features['VirtualAlloc_import'] = 1
                    if 'CreateRemoteThread' in func_name: features['CreateRemoteThread_import'] = 1
                    if 'WriteProcessMemory' in func_name: features['WriteProcessMemory_import'] = 1
                    if 'NtCreateSection' in func_name: features['NtCreateSection_import'] = 1
                    if 'RegSetValueEx' in func_name: features['RegSetValueEx_import'] = 1
                    if 'CryptEncrypt' in func_name: features['CryptEncrypt_import'] = 1
                    if 'SetWindowsHookEx' in func_name: features['SetWindowsHookEx_import'] = 1
                    if 'LoadLibrary' in func_name: features['LoadLibrary_import'] = 1
                    if 'GetProcAddress' in func_name: features['GetProcAddress_import'] = 1
        
        # Simple check for UPX packer signature in file content (can be extended)
        if re.search(b'UPX!', file_content):
            features['is_packed_upx'] = 1

        pe.close() # Important to close the PE object to release file handles

    except pefile.PEFormatError:
        # print(f"File {filepath} is not a valid PE file.")
        return None # Not a PE file, skip or handle differently
    except Exception as e:
        print(f"Error processing file {filepath}: {e}")
        return None
    
    return features

# You can add a main guard for testing if you want
if __name__ == '__main__':
    # Example usage:
    # Make sure you have a test_benign.exe and test_ransomware.exe in your data/raw_samples/
    benign_features = extract_pe_features('../data/raw_samples/test_benign.exe')
    if benign_features:
        print("Benign File Features:", benign_features)

    ransomware_features = extract_pe_features('../data/raw_samples/test_ransomware.exe')
    if ransomware_features:
        print("Ransomware File Features:", ransomware_features)