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

# 2. Create or ensure existing tables
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
        FOREIGN KEY (binary_id) REFERENCES binary (id)
    )
''')

# New table to store ARM64 instructions
cursor.execute('''
    CREATE TABLE IF NOT EXISTS arm_asm_instructions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        binary_id   INTEGER NOT NULL,
        instruction TEXT,
        FOREIGN KEY (binary_id) REFERENCES binary (id)
    )
''')

# NEW: Table for load commands
cursor.execute('''
    CREATE TABLE IF NOT EXISTS load_commands (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        binary_id  INTEGER NOT NULL,
        command    TEXT,
        cmdsize    TEXT,
        details    TEXT,
        FOREIGN KEY (binary_id) REFERENCES binary (id)
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
    try:
        cmd = ["otool", "-hv", file_path]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        lines = []
        for line in output.splitlines():
            line = line.strip()
            # If line starts with 'MH_' or '0x', it's likely our data line
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
            headers_info.append(
                (magic, cputype, cpusubtype, caps, filetype, ncmds, sizeofcmds, flags)
            )

        return headers_info

    except subprocess.CalledProcessError:
        # Not a valid Mach-O or otool error
        return []


def get_arm64_instructions(file_path):
    """
    Call 'otool -arch arm64 -tV' to retrieve the assembly for ARM64.
    Parse each line for the instruction mnemonic (e.g., 'mov', 'ldr', 'adr').
    Return a list of instructions.
    """
    try:
        cmd = ["otool", "-arch", "arm64", "-tV", file_path]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError:
        # Possibly not ARM64 or not a valid Mach-O
        return []
    except FileNotFoundError:
        # 'otool' not found or other OS-level error
        return []

    instructions = []
    for line in output.splitlines():
        # Typical line format:
        # "0000000100003ae8    add    x0, x0, #0x100"
        # We do a naive check for a leading address
        line = line.strip()
        if re.match(r'^[0-9A-Fa-f]+\s', line):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                instructions.append(parts[1])

    return instructions


def store_arm64_instructions(binary_id, instructions):
    """
    For a given binary ID, store the list of instructions into `arm_asm_instructions`.
    """
    for instr in instructions:
        cursor.execute(
            "INSERT INTO arm_asm_instructions (binary_id, instruction) VALUES (?, ?)",
            (binary_id, instr)
        )
    conn.commit()


# NEW: Functions to collect and store load commands
def get_load_commands(file_path):
    """
    Call 'otool -l' to list load commands, parse out each 'Load command N'
    block, and extract 'cmd', 'cmdsize', and the additional details.
    """
    commands = []
    try:
        output = subprocess.check_output(["otool", "-l", file_path],
                                         stderr=subprocess.STDOUT,
                                         text=True)
        lines = output.splitlines()

        current_load_cmd = None  # Start with None, so we know if we've hit a "Load command ..." line yet

        for line in lines:
            line = line.strip()

            # Start of a load command block
            if line.startswith("Load command"):
                # If we already have a load command dict, store it first
                if current_load_cmd is not None:
                    commands.append(current_load_cmd)
                # Create a new dict for the next block
                current_load_cmd = {"command": "", "cmdsize": "", "details": []}

            elif current_load_cmd is not None:
                # We’re inside a load command block. Let’s parse known fields.
                if line.startswith("cmd "):
                    # e.g. 'cmd LC_SEGMENT_64'
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        current_load_cmd["command"] = parts[1]

                elif line.startswith("cmdsize "):
                    # e.g. 'cmdsize 72'
                    parts = line.split()
                    if len(parts) >= 2:
                        current_load_cmd["cmdsize"] = parts[1]

                # Save everything as part of 'details'
                current_load_cmd["details"].append(line)

        # Append the last load command, if any
        if current_load_cmd is not None:
            commands.append(current_load_cmd)

    except subprocess.CalledProcessError:
        # If 'otool -l' fails, just return an empty list
        pass

    return commands


def store_load_commands(binary_id, commands):
    """
    For a given binary ID, store each load command in the 'load_commands' table.
    """
    for cmd_info in commands:
        command = cmd_info.get("command", "")
        cmdsize = cmd_info.get("cmdsize", "")
        # Join all details lines with a newline
        details = "\n".join(cmd_info.get("details", []))
        cursor.execute('''
            INSERT INTO load_commands (binary_id, command, cmdsize, details)
            VALUES (?, ?, ?, ?)
        ''', (binary_id, command, cmdsize, details))

    conn.commit()


def process_file(file_path):
    """
    Insert the file path into `binary` and gather Mach-O header data
    for insertion into `binary_header`. Also harvest ARM64 instructions
    and load commands.
    """
    # Insert path into `binary` table
    cursor.execute("INSERT INTO binary (path) VALUES (?)", (file_path,))
    binary_id = cursor.lastrowid

    # Insert Mach-O header info
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

    # Harvest ARM64 instructions (if applicable)
    arm64_instructions = get_arm64_instructions(file_path)
    if arm64_instructions:
        store_arm64_instructions(binary_id, arm64_instructions)

    # NEW: Harvest load commands
    load_cmds = get_load_commands(file_path)
    if load_cmds:
        store_load_commands(binary_id, load_cmds)


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
        description="Scan directories for Mach-O binaries, store their headers, load commands, and harvest ARM64 instructions into a SQLite database."
    )
    parser.add_argument(
        "directories",
        nargs="*",
        default=["/sbin/"],
        help="One or more directories to scan. If none are specified, defaults to /sbin/."
    )
    args = parser.parse_args()

    # Process each directory in the list
    for directory in args.directories:
        if os.path.isdir(directory):
            walk_directory(directory)
        else:
            print(f"Warning: {directory} is not a valid directory or not accessible.")

    # Close DB
    conn.close()
    print("Done scanning, storing Mach-O headers, load commands, and ARM64 instructions into SQLite.")


if __name__ == "__main__":
    main()
