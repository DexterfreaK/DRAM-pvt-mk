#!/bin/python3

# Script that takes in object file as input and outputs final KLEE executable IR
# Input: object code file path

import os
import sys
import tempfile
import subprocess

object_file = sys.argv[1]
prog_name   = os.path.basename(object_file)
if not os.path.exists(object_file):
    print(f"Path : {object_file} does not exist")
    exit(1)


##### Step-1 Lift the object file using bpf_lifter and store in temp file
lifted_prog_ir_fd, lifted_prog_ir_file = tempfile.mkstemp()

try:
    result = subprocess.run(["bpflifter_cli", f"{object_file}", "."], stdout=lifted_prog_ir_fd)
except:
    print("Error in lifting the program")
    exit(1)

