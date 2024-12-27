#!/usr/bin/env python3

import os
import re
import subprocess
import sqlite3
import argparse

# 1. Initialize or open the SQLite database
DB_PATH = 'mach_o_binaries.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# 2. Create the tables if they don’t already exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS binary (
        id   INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS binary_header (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        binary_id   INTEGER NOT NULL,
        magic       TEXT,
        cputype     TEXT,
        cpusubtype  TEXT,
        caps        TEXT,
        filetype    TEXT,
        ncmds       INTEGER,
        sizeofcmds  INTEGER,
        flags       TEXT,
        FOREIGN KEY (binary_id) REFERENCES binaries (id)
    )
''')
conn.commit()

def is_mach_o(file_path):
    """
    A quick check to see if the file is likely Mach-O by reading its magic bytes.
    This isn’t foolproof, but is often sufficient.
    """
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
        return magic in [
            b'\xFE\xED\xFA\xCE',  # MH_MAGIC
            b'\xCE\xFA\xED\xFE',  # MH_CIGAM
            b'\xFE\xED\xFA\xCF',  # MH_MAGIC_64
            b'\xCF\xFA\xED\xFE',  # MH_CIGAM_64
            b'\xCA\xFE\xBA\xBE',  # FAT_MAGIC
            b'\xBE\xBA\xFE\xCA',  # FAT_CIGAM
            b'\xCA\xFE\xBA\xBF',  # FAT_MAGIC_64
            b'\xBF\xBA\xFE\xCA'   # FAT_CIGAM_64
        ]
    except:
        return False

def get_mach_header_info(file_path):
    """
    Call 'otool -hv' and parse out the relevant fields:
      magic, cputype, cpusubtype, caps, filetype, ncmds, sizeofcmds, flags
    """
    import re
    try:
        cmd = ["otool", "-hv", file_path]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        lines = []
        for line in output.splitlines():
            line = line.strip()
            # If line starts with 'MH_' or '0xFEED', it's likely our data line
            if re.match(r'(MH_|0x)', line):
                lines.append(line)

        headers_info = []
        for hdr_line in lines:
            parts = hdr_line.split()
            if len(parts) < 7:
                continue
            magic = parts[0]
            cputype = parts[1]
            cpusubtype = parts[2]
            caps = parts[3]
            filetype = parts[4]
            ncmds = parts[5]
            sizeofcmds = parts[6]
            flags = " ".join(parts[7:]) if len(parts) > 7 else ""
            headers_info.append((magic, cputype, cpusubtype, caps, filetype, ncmds, sizeofcmds, flags))

        return headers_info

    except subprocess.CalledProcessError:
        # Not a valid Mach-O or otool error
        return []

def process_file(file_path):
    """
    Insert the file path into `binary` and gather Mach-O header data
    for insertion into `binary_header`.
    """
    cursor.execute("INSERT INTO binary (path) VALUES (?)", (file_path,))
    binary_id = cursor.lastrowid

    header_list = get_mach_header_info(file_path)
    for (magic, cputype, cpusubtype, caps, filetype, ncmds, sizeofcmds, flags) in header_list:
        cursor.execute("""
            INSERT INTO binary_header (
                binary_id,
                magic,
                cputype,
                cpusubtype,
                caps,
                filetype,
                ncmds,
                sizeofcmds,
                flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            binary_id,
            magic,
            cputype,
            cpusubtype,
            caps,
            filetype,
            int(ncmds) if ncmds.isdigit() else None,
            int(sizeofcmds) if sizeofcmds.isdigit() else None,
            flags
        ))
    conn.commit()

def walk_directory(root_dir):
    """
    Recursively walk the specified directory, identify Mach-O files,
    and process them.
    """
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            # Skip broken symlinks or unreadable files
            if not os.path.isfile(file_path):
                continue
            if is_mach_o(file_path):
                process_file(file_path)

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Scan a directory for Mach-O binaries and store their headers into a SQLite database."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="/sbin/",
        help="Directory to scan (defaults to /sbin/ if not specified)."
    )
    args = parser.parse_args()

    # Perform the scan
    walk_directory(args.directory)

    # Close DB
    conn.close()
    print("Done scanning and storing Mach-O headers into SQLite.")

if __name__ == "__main__":
    main()