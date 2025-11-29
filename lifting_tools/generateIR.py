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

KLEE_BPF_CFLAGS = "-I/home/anakin/DRACO-pvt/examples/headers/ -I/usr/include/x86_64-linux-gnu -I/home/anakin/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/"

def run_cmd(cmd, description, capture_output=True, check=True):
    """Execute a command and handle errors"""
    print(f"[{description}] Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, capture_output=capture_output, text=True)
    if check and result.returncode != 0:
        print(f"ERROR: {description} failed (code {result.returncode})")
        if result.stdout:
            print(f"stdout:\n{result.stdout}")
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        exit(1)
    if result.stdout and result.stdout.strip():
        print(result.stdout)
    return result

object_file = sys.argv[1]
prog_name   = sys.argv[2] if len(sys.argv) > 3 else ""   # Name of the leader program that will be called
if not os.path.exists(object_file):
    print(f"Path : {object_file} does not exist")
    exit(1)


##### Step-1 Lift the object file using bpf_lifter and store in temp file along with metadata
print(f"\n[Step 1] Lifting object file: {object_file}")
temp_dir = tempfile.mkdtemp()
lifted_ir_fd, lifted_ir_file = tempfile.mkstemp(dir=temp_dir)
map_dump_file = f"{temp_dir}/map_dump"
prog_dump_file = f"{temp_dir}/prog_dump"
print(f"Working dir: {temp_dir}")

try:

    result = subprocess.run(["bpflifter_cli", object_file, temp_dir], stdout=lifted_ir_fd, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"ERROR: Lifting failed: {result.stderr}")
        exit(1)
    
    run_cmd(["opt", "-O3", "-S", lifted_ir_file, "-o", lifted_ir_file], "Optimize IR")
except Exception as e:
    print(f"ERROR: {e}")
    exit(1)


##### Step-2 get offset and relocation information form elf file
print(f"[Step 2] Extracting relocation info")
def gen_reloc_dump(elf, dump_dir) -> bool:
    with open(elf, 'rb') as f:
        elffile = ELFFile(f)
        relxdp_section = elffile.get_section_by_name('.relxdp')
        if not isinstance(relxdp_section, RelocationSection):
            return False
        symtab = elffile.get_section(relxdp_section['sh_link'])
        relxdp_data = relxdp_section.data()
        print("[relocation data] (hex) :", relxdp_data.hex())
        num_entries = relxdp_section.num_relocations()
        print(f"Number of relocation entries in .relxdp: {num_entries}")
        with open(os.path.join(dump_dir,"map_offset_mapping"), 'w') as dump_file:
            for reloc in relxdp_section.iter_relocations():
                offset = reloc['r_offset']
                sym_index = reloc['r_info_sym']
                symbol = symtab.get_symbol(sym_index)
                dump_file.write(f"{int(offset)},{str(symbol.name)}\n")
        return True

do_relocate = gen_reloc_dump(object_file, temp_dir)
map_offset_mapping = os.path.join(temp_dir,"map_offset_mapping")
print(f"Has .relxdp: {do_relocate}")

##### Step-3 apply llvm function pass on lifter and opt IR
print(f"[Step 3] Applying function pass to remove map globals")

func_pass_lib = os.getenv("FUNC_PASS_LIB", "/home/anakin/DRACO-pvt/lifting_tools/llvm_func_pass/build/libfunc_pass.so")
if not os.path.exists(func_pass_lib):
    print(f"ERROR: Function pass library not found: {func_pass_lib}")
    exit(1)

if do_relocate:
    run_cmd([
        "opt", "-load", func_pass_lib, f"-load-pass-plugin={func_pass_lib}",
        "-passes=custom-bpf-pass", "-map-config", map_offset_mapping,
        lifted_ir_file, "-o", lifted_ir_file
    ], "Remove map globals")
else:
    print("Skipping function pass (no relocations found)")


# exit(0)

##### Step-4 template generation
print(f"[Step 4] Generating template code")
def generate_code(config, template_path='.', template_filename='draco_template.j2', output_path='generated_xdp.tmpl.c'):
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template(template_filename)
    rendered = template.render({'maps': config['maps'], 'extern_func': config['extern_func']})
    with open(output_path, 'w') as f:
        f.write(rendered)

def generate_config(dir):
    config = {}
    with open(os.path.join(dir,"prog_dump"),'r') as f:
        names = [n.strip() for n in f.readlines() if n.strip()]
        func_name = prog_name if prog_name in names else names[0]
        config["extern_func"] = str(func_name)
    
    config["maps"] = []
    with open(os.path.join(dir,"map_dump"), 'r') as f:
        for line in f:
            if line.strip():
                info = line.strip().split(',')
                config["maps"].append({
                    "name": info[0], "type": int(info[1]), "key_size": int(info[2]),
                    "value_size": int(info[3]), "max_entries": int(info[4]),
                    "ops": ["lookup","update","delete"]
                })
    return config

config = generate_config(temp_dir)
gen_cpp_path = os.path.join(temp_dir, "cpp_generated_code.c")
generate_code(config=config, template_path="/home/anakin/DRACO-pvt/lifting_tools", output_path=gen_cpp_path)
print(f"Function: {config['extern_func']}, Maps: {len(config['maps'])}")


##### Step-5 compile template
print(f"[Step 5] Compiling template")
klee_include = os.environ.get("KLEE_INCLUDE", "/home/anakin/DRACO-pvt/klee/include")
env = os.environ.copy()
env["KLEE_INCLUDE"] = klee_include

result = subprocess.run(["make", "compile-template", f"input_file={gen_cpp_path}", f"output_file={gen_cpp_path}"], env=env)
if result.returncode != 0:
    clang_cmd = ["clang-13", "-target", "bpf", "-DKLEE_VERIFICATION", "-DVERIFY_INTERACTIONS"] + \
        KLEE_BPF_CFLAGS.strip().split() + ["-I", klee_include, "-D__USE_VMLINUX__", "-D__TARGET_ARCH_x86",
        "-DBPF_NO_PRESERVE_ACCESS_INDEX", "-Wall", "-Wno-unused-value", "-Wno-unused-variable",
        "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types", "-Werror", "-fno-discard-value-names",
        "-fno-builtin", "-O0", "-emit-llvm", "-c", "-g", gen_cpp_path, "-o", gen_cpp_path]
    run_cmd(clang_cmd, "Compile template (fallback)")

##### Step-6 Apply ext sym pass
print(f"[Step 6] Applying ext sym pass")
ext_pass_lib = os.getenv("EXT_SYM_PASS_LIB")
if ext_pass_lib and os.path.exists(ext_pass_lib):
    run_cmd(["opt", f"-load-pass-plugin={ext_pass_lib}", "-passes=int-to-ext", gen_cpp_path, "-o", gen_cpp_path], "Ext sym pass", check=False)

##### Step-7 link both the transformed IRs
print(f"[Step 7] Linking IRs")
final_ir_path = os.path.join(os.path.dirname(object_file),"final_linked_ir.bc")
run_cmd(["llvm-link", gen_cpp_path, lifted_ir_file, "-o", final_ir_path], "Link IRs")
print(f"Output: {final_ir_path}")
