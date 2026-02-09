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

# Build KLEE_BPF_CFLAGS dynamically based on KRAKENGUARD_HOME
def get_klee_bpf_cflags():
    krakenguard_home = os.getenv("KRAKENGUARD_HOME")
    if krakenguard_home:
        examples_headers = f"{krakenguard_home}/examples/headers"
        libbpf_include = f"{krakenguard_home}/ebpf-se/libbpf-stubbed/src/build/usr/include"
    else:
        # Fallback to development paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        examples_headers = f"{project_root}/examples/headers"
        libbpf_include = f"{project_root}/ebpf-se/libbpf-stubbed/src/build/usr/include"
    return f"-I{examples_headers} -I/usr/include/x86_64-linux-gnu -I{libbpf_include}"

KLEE_BPF_CFLAGS = get_klee_bpf_cflags()

# Global variable to track detected program type
program_type = "xdp"  # default

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

# Parse remaining arguments - detect if arg is a yaml file or a function name
prog_name = ""
program_config_path = ""
for arg in sys.argv[2:]:
    if arg.endswith('.yaml') or arg.endswith('.yml'):
        program_config_path = arg
    elif arg.strip():  # Non-empty, non-yaml is treated as function name
        prog_name = arg

if not os.path.exists(object_file):
    print(f"Path : {object_file} does not exist")
    exit(1)

# Load program config if provided
program_config = None
if program_config_path and os.path.exists(program_config_path):
    with open(program_config_path, 'r') as f:
        program_config = yaml.safe_load(f)
    print(f"Loaded program config: {program_config_path}")
elif program_config_path:
    print(f"WARNING: Program config file not found: {program_config_path}")


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
        # Find relocation section - try common names like .relxdp, .relxdp-*, etc.
        relxdp_section = None
        for section in elffile.iter_sections():
            if isinstance(section, RelocationSection) and section.name.startswith('.rel'):
                # Skip non-program sections like .rela.BTF, .rel.debug_*, etc.
                if any(skip in section.name for skip in ['.BTF', '.debug', '.eh_frame']):
                    continue
                # Look for program-related relocation sections (xdp, kprobe, tracepoint, etc.)
                # Skip debug and BTF sections
                if '.debug' in section.name or '.BTF' in section.name:
                    continue
                if 'xdp' in section.name or section.name == '.rel.text' or \
                   'kprobe' in section.name or 'kretprobe' in section.name or \
                   'tracepoint' in section.name or 'socket' in section.name:
                    relxdp_section = section
                    print(f"Found relocation section: {section.name}")
                    # Detect program type from section name
                    global program_type
                    if 'kprobe' in section.name or 'kretprobe' in section.name:
                        program_type = 'kprobe'
                    elif 'tracepoint' in section.name or 'raw_tracepoint' in section.name:
                        program_type = 'tracepoint'
                    elif 'socket' in section.name:
                        program_type = 'socket'
                    else:
                        program_type = 'xdp'
                    print(f"Detected program type: {program_type}")
                    break
        if not isinstance(relxdp_section, RelocationSection):
            return False
        symtab = elffile.get_section(relxdp_section['sh_link'])
        relxdp_data = relxdp_section.data()
        print("[relocation data] (hex) :", relxdp_data.hex())
        num_entries = relxdp_section.num_relocations()
        print(f"Number of relocation entries in {relxdp_section.name}: {num_entries}")
        
        # Extract function start addresses from xdp section symbols
        func_offsets = []
        for i in range(symtab.num_symbols()):
            sym = symtab.get_symbol(i)
            # Check if symbol is a function in xdp section
            if sym['st_info']['type'] == 'STT_FUNC':
                func_offsets.append(int(sym['st_value']))
        func_offsets.sort()
        print(f"Function start offsets: {func_offsets}")
        
        # Collect all relocations
        relocations = []
        global_offsets = set()  # Track global offsets to avoid overwriting
        for reloc in relxdp_section.iter_relocations():
            offset = int(reloc['r_offset'])
            sym_index = reloc['r_info_sym']
            symbol = symtab.get_symbol(sym_index)
            relocations.append((offset, str(symbol.name)))
            global_offsets.add(offset)
        
        with open(os.path.join(dump_dir,"map_offset_mapping"), 'w') as dump_file:
            # Write global offset mappings first
            for offset, map_name in relocations:
                dump_file.write(f"{offset},{map_name}\n")
            
            # For each relocation, also write local offsets relative to each function
            # The bpflifter uses local offsets within functions, so we need to map those too
            # BUT only if the local offset doesn't conflict with a global offset
            for global_offset, map_name in relocations:
                for func_start in func_offsets:
                    if func_start > 0 and global_offset > func_start:
                        local_offset = global_offset - func_start
                        # Only add if this local offset doesn't conflict with a global offset
                        if local_offset not in global_offsets:
                            dump_file.write(f"{local_offset},{map_name}\n")
                            print(f"  Added local offset: {local_offset} (global {global_offset} - func {func_start}) -> {map_name}")
                        else:
                            print(f"  Skipped local offset {local_offset} (conflicts with global offset)")
        return True

do_relocate = gen_reloc_dump(object_file, temp_dir)
map_offset_mapping = os.path.join(temp_dir,"map_offset_mapping")
print(f"Has .relxdp: {do_relocate}")

##### Step-3 apply llvm function pass on lifter and opt IR
print(f"[Step 3] Applying function pass to remove map globals")

# Get FUNC_PASS_LIB from environment, with fallback using KRAKENGUARD_HOME or script directory
krakenguard_home = os.getenv("KRAKENGUARD_HOME")
if krakenguard_home:
    default_func_pass = f"{krakenguard_home}/lib/libfunc_pass.so"
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_func_pass = f"{script_dir}/llvm_func_pass/build/libfunc_pass.so"
func_pass_lib = os.getenv("FUNC_PASS_LIB", default_func_pass)
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
def generate_code(config, template_path='.', template_filename='draco_template.j2', output_path='generated_xdp.tmpl.c', function_pass_ran=False):
    # Get verification_helpers path based on KRAKENGUARD_HOME
    krakenguard_home = os.getenv("KRAKENGUARD_HOME")
    if krakenguard_home:
        verification_helpers_path = f"{krakenguard_home}/verification_tools/verification_helpers.h"
    else:
        # Fallback to relative path from project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        verification_helpers_path = f"{project_root}/verification_tools/verification_helpers.h"
    
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template(template_filename)
    rendered = template.render({
        'maps': config['maps'],
        'extern_func': config['extern_func'],
        'map_init': config.get('map_init', []),
        'function_pass_ran': function_pass_ran,
        'verification_helpers_path': verification_helpers_path
    })
    with open(output_path, 'w') as f:
        f.write(rendered)

def generate_config(dir, program_config=None):
    config = {}
    
    # Read all program names from prog_dump
    with open(os.path.join(dir, "prog_dump"), 'r') as f:
        all_progs = [n.strip() for n in f.readlines() if n.strip()]
    config["all_progs"] = all_progs
    func_name = prog_name if prog_name in all_progs else (all_progs[0] if all_progs else "")
    config["extern_func"] = str(func_name)
    config["program_type"] = program_type  # xdp, kprobe, tracepoint, etc.
    
    # Get tailcall config if available
    tailcalls_config = {}
    if program_config and "tailcalls" in program_config:
        tailcalls_config = program_config["tailcalls"]
    
    # Get map_init config if available
    config["map_init"] = []
    if program_config and "map_init" in program_config:
        config["map_init"] = program_config["map_init"]
    
    config["maps"] = []
    with open(os.path.join(dir, "map_dump"), 'r') as f:
        for line in f:
            if line.strip():
                info = line.strip().split(',')
                map_name = info[0]
                
                # Skip .rodata and other non-map sections (including object-prefixed sections)
                if map_name.startswith('.rodata') or map_name.startswith('.bss') or map_name.startswith('.data'):
                    continue
                if '.bss' in map_name or '.data' in map_name or '.rodata' in map_name:
                    continue
                
                map_type = int(info[1])
                
                map_entry = {
                    "name": map_name,
                    "type": map_type,
                    "key_size": int(info[2]),
                    "value_size": int(info[3]),
                    "max_entries": int(info[4]),
                    "ops": ["lookup", "update", "delete"],
                    "is_prog_array": (map_type == 3)  # BPF_MAP_TYPE_PROG_ARRAY
                }
                
                # Add tailcall entries if this is a prog_array with config
                if map_entry["is_prog_array"] and map_name in tailcalls_config:
                    entries = tailcalls_config[map_name]
                    # Validate function names against prog_dump
                    for entry in entries:
                        if entry["function"] not in all_progs:
                            print(f"WARNING: Tailcall function '{entry['function']}' not found in prog_dump")
                    map_entry["tailcall_entries"] = entries
                    print(f"Added {len(entries)} tailcall entries for map '{map_name}'")
                
                config["maps"].append(map_entry)
    return config

config = generate_config(temp_dir, program_config)
gen_cpp_path = os.path.join(temp_dir, "cpp_generated_code.c")
# Get template path from KRAKENGUARD_HOME or use script directory
krakenguard_home = os.getenv("KRAKENGUARD_HOME")
if krakenguard_home:
    template_path = f"{krakenguard_home}/lifting_tools"
else:
    template_path = os.path.dirname(os.path.abspath(__file__))
generate_code(config=config, template_path=template_path, output_path=gen_cpp_path, function_pass_ran=do_relocate)
print(f"Function: {config['extern_func']}, Maps: {len(config['maps'])}")
# Debug: verify file was written
if not os.path.exists(gen_cpp_path):
    print(f"ERROR: Template file not written: {gen_cpp_path}")
    exit(1)
# Show prog_array maps with tailcall entries
for m in config['maps']:
    if m.get('tailcall_entries'):
        print(f"  - {m['name']}: {len(m['tailcall_entries'])} tailcall entries")


##### Step-5 compile template
print(f"[Step 5] Compiling template")
# Get KLEE_INCLUDE from environment, with fallback using KRAKENGUARD_HOME
krakenguard_home = os.getenv("KRAKENGUARD_HOME")
if krakenguard_home:
    default_klee_include = f"{krakenguard_home}/klee/include"
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_klee_include = f"{project_root}/klee/include"
klee_include = os.environ.get("KLEE_INCLUDE", default_klee_include)

# Compile the template directly with clang (skip make to avoid dependency issues)
clang_cmd = [
    "clang-13", "-target", "bpf", "-DKLEE_VERIFICATION", "-DVERIFY_INTERACTIONS"
] + KLEE_BPF_CFLAGS.strip().split() + [
    "-I", klee_include, "-D__USE_VMLINUX__", "-D__TARGET_ARCH_x86",
    "-DBPF_NO_PRESERVE_ACCESS_INDEX", "-Wall", "-Wno-unused-value", "-Wno-unused-variable",
    "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types", "-Wno-unused-function",
    "-fno-discard-value-names", "-fno-builtin", "-O0", "-emit-llvm", "-c", "-g",
    gen_cpp_path, "-o", gen_cpp_path
]
run_cmd(clang_cmd, "Compile template")

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
