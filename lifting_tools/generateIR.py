#!/bin/python3

# Script that takes in object file as input and outputs final KLEE executable IR
# Input: object code file path

import os
import sys
import tempfile
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from jinja2 import Environment, FileSystemLoader
import yaml

object_file = sys.argv[1]
prog_name   = os.path.basename(object_file)
if not os.path.exists(object_file):
    print(f"Path : {object_file} does not exist")
    exit(1)


##### Step-1 Lift the object file using bpf_lifter and store in temp file along with metadata
temp_dir = tempfile.mkdtemp()
lifted_ir_fd, lifted_ir_file = tempfile.mkstemp(dir=temp_dir)
map_dump_file = f"{temp_dir}/map_dump"
prog_dump_file = f"{temp_dir}/prog_dump"

print(f"temproary working dir for process {os.getpid()} is {temp_dir}")
try:
    # lift
    result = subprocess.run(["bpflifter_cli", f"{object_file}", f"{temp_dir}"], stdout=lifted_ir_fd)
    # optimize
    result = subprocess.run(["opt", "-O3", "-S", f"{lifted_ir_file}", "-o", f"{lifted_ir_file}"])
except Exception as e:
    print("Error in lifting the program : ", e)
    exit(1)


##### Step-2 get offset and relocation information form elf file
def gen_reloc_dump(elf, dump_dir) -> bool:
    with open(elf, 'rb') as f:
        elffile = ELFFile(f)
        relxdp_section = elffile.get_section_by_name('.relxdp')
        if not isinstance(relxdp_section, RelocationSection):
            return False
        symtab = elffile.get_section(relxdp_section['sh_link'])

        with open(os.path.join(dump_dir,"map_offset_mapping"), 'w') as dump_file:
            for reloc in relxdp_section.iter_relocations():
                # Extract relocation metadata
                offset = reloc['r_offset']
                sym_index = reloc['r_info_sym']
                
                # Resolve symbol details
                symbol = symtab.get_symbol(sym_index)
                sym_name = symbol.name

                dump_file.write(f"{int(offset)},{str(sym_name)}\n")
        
        return True

do_relocate = gen_reloc_dump(object_file, temp_dir)
map_offset_mapping = os.path.join(temp_dir,"map_offset_mapping")

##### Step-3 apply llvm function pass on lifter and opt IR
func_pass_lib = os.getenv("FUNC_PASS_LIB")
try:
    if do_relocate:
        result = subprocess.run(["opt", "-load", f"{func_pass_lib}", f"-load-pass-plugin={func_pass_lib}", f"-passes=custom-bpf-pass", '-map-config', f"{map_offset_mapping}", f"{lifted_ir_file}", '-o', f"{lifted_ir_file}"])
except Exception as e:
    print("Error in applying function pass : ",e)
    exit(1)


##### Step-4 template generation
def generate_code(config, template_path='.', template_filename='draco_template.j2', output_path='generated_xdp.tmpl.c'):
    # Set the template directory
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)
    
    # Get the template from the specified filename
    template = env.get_template(template_filename)
    
    # Render the template with the provided configuration
    rendered = template.render({
        'maps': config['maps'],
        'extern_func': config['extern_func']
    })
    
    # Write the rendered output to the specified path
    with open(output_path, 'w') as f:
        f.write(rendered)

def generate_config(dir):
    config = {}
    with open(os.path.join(dir,"prog_dump"),'r') as f:
        func_name = f.read()
        func_name = func_name.strip()
        config["extern_func"] = str(func_name)
    
    config["maps"] = []
    with open(os.path.join(dir,"map_dump"), 'r') as f:
        for line in f.readlines():
            if line.strip() == "":
                continue
            info = line.strip().split(',')
            mapinfo = {}
            mapinfo["name"] = info[0]
            mapinfo["type"] = int(info[1])
            mapinfo["key_size"] = int(info[2])
            mapinfo["value_size"] = int(info[3])
            mapinfo["max_entries"] = int(info[4])
            mapinfo["ops"] = ["lookup"]
            config["maps"].append(mapinfo)

    return config

config = generate_config(temp_dir)
gen_cpp_path = os.path.join(temp_dir, "cpp_generated_code.c")
print(config)
# TODO: update
template_path = "/home/jainil/Draco/DRACO-verifier/lifting_tools"
generate_code(config=config,template_path=template_path,output_path=gen_cpp_path)


##### Step-5 compile template
try:
    result = subprocess.run(["make", "compile-template", f"input_file={gen_cpp_path}", f"output_file={gen_cpp_path}"])
except Exception as e:
    print("error in compiling template : ", e)
    exit(1)


##### Step-6 Apply ext sym pass
ext_pass_lib = os.getenv("EXT_SYM_PASS_LIB")
try:
    result = subprocess.run(["opt", f"-load-pass-plugin={ext_pass_lib}", f"-passes=int-to-ext", f"{gen_cpp_path}", '-o', f"{gen_cpp_path}"])
except Exception as e:
    print("Error in applying function pass : ", e)
    exit(1)


##### Step-7 link both the transformed IRs
final_ir_path = os.path.join(os.path.dirname(object_file),"final_linked_ir.bc")
try:
    result = subprocess.run(["llvm-link", f"{gen_cpp_path}", f"{lifted_ir_file}", "-o", f"{final_ir_path}"])
except Exception as e:
    print("error in linking both irs : ", e)
    exit(1)
