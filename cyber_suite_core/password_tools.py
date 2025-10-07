import secrets
import string
import hashlib
from typing import Union, Optional

def generate_password(length: int, include_uppercase: bool, include_lowercase: bool, include_digits: bool, include_symbols: bool) -> Union[str, None]:
    """Generates a secure, random password based on specified criteria."""
    alphabet = ''
    if include_uppercase:
        alphabet += string.ascii_uppercase
    if include_lowercase:
        alphabet += string.ascii_lowercase
    if include_digits:
        alphabet += string.digits
    if include_symbols:
        alphabet += string.punctuation

    if not alphabet:
        return None

    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def audit_password_hash(hash_to_crack: str, wordlist_path: str, hash_algorithm: str = 'sha256') -> Optional[str]:
    """
    Audits a password's strength by attempting to crack it using a wordlist.
    
    Disclaimer: This tool is for educational purposes and for auditing the strength
    of your own passwords only. Do not use it for any unauthorized activities.
    """
    hash_to_crack = hash_to_crack.lower() # Ensure case-insensitivity for hash comparison

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue

                # Hash the word using the specified algorithm
                if hash_algorithm == 'md5':
                    hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
                elif hash_algorithm == 'sha1':
                    hashed_word = hashlib.sha1(word.encode('utf-8')).hexdigest()
                elif hash_algorithm == 'sha256':
                    hashed_word = hashlib.sha256(word.encode('utf-8')).hexdigest()
                elif hash_algorithm == 'sha512':
                    hashed_word = hashlib.sha512(word.encode('utf-8')).hexdigest()
                else:
                    raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
                
                if hashed_word == hash_to_crack:
                    return word
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
    except ValueError as e:
        raise e
    except Exception as e:
        raise Exception(f"An error occurred during cracking: {e}")

    return None # Password not found in wordlist
