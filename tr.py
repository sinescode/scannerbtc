#!/usr/bin/env python3
"""
Complete a BIP39 C++ header file to contain the full 2048-word English wordlist.
If BIP39_WORD_COUNT is missing, it will be added.
The array size and content are replaced with the official list from the mnemonic module.
"""

import re
import sys
from mnemonic import Mnemonic

def get_official_wordlist():
    """Return the official BIP39 English wordlist as a list."""
    mnemo = Mnemonic("english")
    return list(mnemo.wordlist)  # 2048 words, sorted

def find_array_bounds(content, array_name="BIP39_WORDLIST"):
    """
    Locate the position of the array declaration and its content.
    Returns (start_of_array_decl, start_of_body, end_of_body, end_of_array_decl)
    where:
      start_of_array_decl : index of the first character of the whole declaration
      start_of_body       : index of the '{' that begins the list
      end_of_body         : index of the '}' that ends the list
      end_of_array_decl   : index of the ';' that terminates the declaration
    """
    # Find the array name followed by optional whitespace and '['
    pattern = re.compile(r'\b' + re.escape(array_name) + r'\s*\[\s*\d+\s*\]\s*=\s*{')
    match = pattern.search(content)
    if not match:
        raise ValueError(f"Could not find declaration of {array_name}.")

    start_decl = match.start()
    start_body = match.end() - 1  # position of the '{'

    # Find matching closing brace
    brace_count = 0
    in_string = False
    end_body = -1
    for i in range(start_body, len(content)):
        ch = content[i]
        if ch == '"' and (i == 0 or content[i-1] != '\\'):
            in_string = not in_string
        if not in_string:
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_body = i
                    break
    if end_body == -1:
        raise ValueError("Could not find closing brace of the wordlist array.")

    # Find the terminating semicolon after the closing brace
    end_decl = content.find(';', end_body)
    if end_decl == -1:
        raise ValueError("Could not find terminating semicolon after the array.")

    return start_decl, start_body, end_body, end_decl

def insert_or_update_word_count(content):
    """
    Ensure that BIP39_WORD_COUNT is defined as 2048.
    If it already exists, update its value. Otherwise, insert it after the includes.
    """
    # Look for existing definition
    pattern = re.compile(r'#define\s+BIP39_WORD_COUNT\s+(\d+)|'
                         r'static\s+constexpr\s+(?:size_t|std::size_t)\s+BIP39_WORD_COUNT\s*=\s*(\d+)\s*;')
    match = pattern.search(content)
    if match:
        # Replace the value with 2048
        if match.group(1):  # #define form
            new_content = re.sub(r'(#define\s+BIP39_WORD_COUNT\s+)\d+', r'\g<1>2048', content)
        else:                # constexpr form
            new_content = re.sub(r'(static\s+constexpr\s+(?:size_t|std::size_t)\s+BIP39_WORD_COUNT\s*=\s*)\d+(\s*;)',
                                 r'\g<1>2048\g<2>', content)
        return new_content, True
    else:
        # Insert after the last #include line (or after #pragma once if no includes)
        lines = content.splitlines(True)
        insert_pos = 0
        for i, line in enumerate(lines):
            if line.startswith('#include'):
                insert_pos = i + 1
            elif line.startswith('#pragma once'):
                insert_pos = i + 1
        # Insert the constant
        const_line = "static constexpr size_t BIP39_WORD_COUNT = 2048;\n"
        lines.insert(insert_pos, const_line)
        return ''.join(lines), False

def update_array_size(content):
    """Ensure the array size in the declaration is 2048."""
    # Match: BIP39_WORDLIST[ any number ]
    pattern = re.compile(r'\b(BIP39_WORDLIST\s*\[\s*)\d+(\s*\])')
    return pattern.sub(r'\g<1>2048\g<2>', content)

def format_wordlist(words):
    """Format the list of words as C++ array entries, one per line."""
    lines = []
    for i, w in enumerate(words):
        if i == len(words) - 1:
            lines.append(f'    "{w}"')
        else:
            lines.append(f'    "{w}",')
    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_bip39_wordlist.py <input.hpp> [output.hpp]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    # Get the official wordlist
    official = get_official_wordlist()
    print(f"Official BIP39 wordlist has {len(official)} words.")

    # Ensure BIP39_WORD_COUNT is correct
    content, count_was_present = insert_or_update_word_count(content)
    if not count_was_present:
        print("Inserted missing BIP39_WORD_COUNT = 2048.")
    else:
        print("Updated BIP39_WORD_COUNT to 2048.")

    # Ensure array size is correct
    content = update_array_size(content)

    # Replace the array body
    try:
        start_decl, start_body, end_body, end_decl = find_array_bounds(content)
    except ValueError as e:
        print(f"Error locating wordlist array: {e}")
        sys.exit(1)

    # Format the new list
    new_array_body = format_wordlist(official)
    new_array = '{\n' + new_array_body + '\n}'

    # Rebuild the file: keep everything up to start_body, then new array, then after end_decl
    new_content = content[:start_body] + new_array + content[end_decl+1:]

    # (Optional) Update the header comment to reflect the fix
    new_content = re.sub(
        r'(// Auto-generated BIP39 English wordlist).*',
        r'\1 (full 2048-word list, regenerated with mnemonic module)',
        new_content,
        count=1
    )

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Successfully wrote corrected wordlist to {output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()