# -*- coding: utf-8 -*-
"""
Created on Mon Jan 13 20:39:25 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("VIRUS ANALYZER")
print(Fore.GREEN+font)


import ast

def is_infinite_loop(node):
    """Heuristic to detect potential infinite loops"""
    if isinstance(node, ast.While):
        # Check for while loops with no break condition or exit clause
        if isinstance(node.test, ast.Name) and node.test.id == 'True':
            return True
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            return True
    elif isinstance(node, ast.For):
        # For loop with no exit condition (e.g., infinite iteration)
        if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name) and node.iter.func.id == 'iter':
            return True
    return False

def find_loops_in_script(script):
    """Finds potential infinite loops in the provided Python script"""
    try:
        # Parse the Python script into an AST
        tree = ast.parse(script)
    except SyntaxError as e:
        print(f"Syntax error in the script: {e}")
        return []

    # Walk through the AST and check for infinite loops
    infinite_loops = []
    for node in ast.walk(tree):
        if is_infinite_loop(node):
            infinite_loops.append(node)

    return infinite_loops

def disassemble_and_analyze(script):
    """Analyze the Python script for potential malicious behavior"""
    infinite_loops = find_loops_in_script(script)

    if infinite_loops:
        print("Potential infinite loops detected!")
        for loop in infinite_loops:
            print(f"Loop at line {loop.lineno}: {ast.dump(loop)}")
    else:
        print("No obvious infinite loops detected.")
    
    # Additional analysis can be added here, such as recursion, imports, or suspicious functions
    # This could include looking for calls to `exec()`, `eval()`, `os.system()`, etc.
    # Add custom heuristics based on your needs.

def main():
    script_path = input("Please enter the path to the Python script to analyze:")
    
    try:
        with open(script_path, 'r') as f:
            script = f.read()
    except FileNotFoundError:
        print("File not found!")
        return
    
    # Perform analysis on the Python script
    disassemble_and_analyze(script)

if __name__ == "__main__":
    main()
