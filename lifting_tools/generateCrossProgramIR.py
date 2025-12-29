#!/bin/python3

# Script for cross-program analysis that takes two object files as input
# and outputs final KLEE executable IR with both programs linked
# Input: prog1_obj prog1_entry prog2_obj prog2_entry [program_config.yaml]

import os
import sys
import tempfile
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from jinja2 import Environment, FileSystemLoader
import yaml

# Get KLEE_BPF_CFLAGS from environment or use default
KLEE_BPF_CFLAGS = os.getenv("KLEE_BPF_CFLAGS", 
    "-I/home/anakin/DRACO-pvt/examples/headers/ -I/usr/include/x86_64-linux-gnu -I/home/anakin/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/")

# Global variables to track detected program types
prog1_type = "xdp"  # default
prog2_type = "xdp"  # default

def run_cmd(cmd, description, capture_output=True, check=True, text=True):
    """Execute a command and handle errors"""
    print(f"[{description}] Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    # For binary output (like llvm-as), don't use text mode
    result = subprocess.run(cmd, capture_output=capture_output, text=text, errors='replace' if text else None)
    if check and result.returncode != 0:
        print(f"ERROR: {description} failed (code {result.returncode})")
        if result.stdout:
            if isinstance(result.stdout, bytes):
                print(f"stdout:\n{result.stdout.decode('utf-8', errors='replace')}")
            else:
                print(f"stdout:\n{result.stdout}")
        if result.stderr:
            if isinstance(result.stderr, bytes):
                print(f"stderr:\n{result.stderr.decode('utf-8', errors='replace')}")
            else:
                print(f"stderr:\n{result.stderr}")
        exit(1)
    if result.stdout:
        if isinstance(result.stdout, bytes):
            output = result.stdout.decode('utf-8', errors='replace')
        else:
            output = result.stdout
        if output.strip():
            print(output)
    return result

def gen_reloc_dump(elf, dump_dir, program_num=1) -> bool:
    """Extract relocation information from ELF file"""
    global prog1_type, prog2_type
    with open(elf, 'rb') as f:
        elffile = ELFFile(f)
        relxdp_section = None
        for section in elffile.iter_sections():
            if isinstance(section, RelocationSection) and section.name.startswith('.rel'):
                if any(skip in section.name for skip in ['.BTF', '.debug', '.eh_frame']):
                    continue
                if '.debug' in section.name or '.BTF' in section.name:
                    continue
                if 'xdp' in section.name or section.name == '.rel.text' or \
                   'kprobe' in section.name or 'kretprobe' in section.name or \
                   'tracepoint' in section.name or 'socket' in section.name:
                    relxdp_section = section
                    print(f"Found relocation section: {section.name}")
                    # Detect program type from section name
                    detected_type = "xdp"
                    if 'kprobe' in section.name or 'kretprobe' in section.name:
                        detected_type = 'kprobe'
                    elif 'tracepoint' in section.name or 'raw_tracepoint' in section.name:
                        detected_type = 'tracepoint'
                    elif 'socket' in section.name:
                        detected_type = 'socket'
                    
                    if program_num == 1:
                        prog1_type = detected_type
                    else:
                        prog2_type = detected_type
                    print(f"Detected program {program_num} type: {detected_type}")
                    break
        if not isinstance(relxdp_section, RelocationSection):
            return False
        symtab = elffile.get_section(relxdp_section['sh_link'])
        relxdp_data = relxdp_section.data()
        print("[relocation data] (hex) :", relxdp_data.hex())
        num_entries = relxdp_section.num_relocations()
        print(f"Number of relocation entries in {relxdp_section.name}: {num_entries}")
        
        func_offsets = []
        for i in range(symtab.num_symbols()):
            sym = symtab.get_symbol(i)
            if sym['st_info']['type'] == 'STT_FUNC':
                func_offsets.append(int(sym['st_value']))
        func_offsets.sort()
        print(f"Function start offsets: {func_offsets}")
        
        relocations = []
        global_offsets = set()
        for reloc in relxdp_section.iter_relocations():
            offset = int(reloc['r_offset'])
            sym_index = reloc['r_info_sym']
            symbol = symtab.get_symbol(sym_index)
            relocations.append((offset, str(symbol.name)))
            global_offsets.add(offset)
        
        with open(os.path.join(dump_dir,"map_offset_mapping"), 'w') as dump_file:
            for offset, map_name in relocations:
                dump_file.write(f"{offset},{map_name}\n")
            
            for global_offset, map_name in relocations:
                for func_start in func_offsets:
                    if func_start > 0 and global_offset > func_start:
                        local_offset = global_offset - func_start
                        if local_offset not in global_offsets:
                            dump_file.write(f"{local_offset},{map_name}\n")
                            print(f"  Added local offset: {local_offset} (global {global_offset} - func {func_start}) -> {map_name}")
                        else:
                            print(f"  Skipped local offset {local_offset} (conflicts with global offset)")
        return True

def lift_single_program(obj_file, temp_dir, program_num=1, program_config=None):
    """Lift a single eBPF program and return config and IR file path"""
    print(f"\n[Lifting Program {program_num}] Object file: {obj_file}")
    
    if not os.path.exists(obj_file):
        print(f"ERROR: Path {obj_file} does not exist")
        exit(1)
    
    # Create temp directory for this program
    prog_temp_dir = os.path.join(temp_dir, f"prog{program_num}")
    os.makedirs(prog_temp_dir, exist_ok=True)
    
    lifted_ir_fd, lifted_ir_file = tempfile.mkstemp(dir=prog_temp_dir, suffix='.ll')
    
    try:
        # Step 1: Lift the object file
        # Close the file descriptor after subprocess completes so we can read the file
        result = subprocess.run(["bpflifter_cli", obj_file, prog_temp_dir], 
                              stdout=lifted_ir_fd, stderr=subprocess.PIPE, text=True)
        os.close(lifted_ir_fd)  # Close file descriptor so we can read the file
        if result.returncode != 0:
            print(f"ERROR: Lifting failed: {result.stderr}")
            exit(1)
        
        # Step 2: Optimize IR
        # Check if the file is binary bitcode or text IR
        # opt can read both, but -S outputs text IR
        # If input is binary, we can use opt without -S first, or convert with llvm-dis
        try:
            with open(lifted_ir_file, 'rb') as f:
                first_bytes = f.read(10)
                is_binary = first_bytes.startswith(b'BC') or first_bytes.startswith(b'\xde\xc0\x17\x0b')
        except Exception as e:
            print(f"WARNING: Could not check file format: {e}")
            is_binary = False
        
        if is_binary:
            # File is binary bitcode
            # Option 1: Use opt without -S to optimize binary, then convert to text
            # Option 2: Convert to text first, then optimize
            # We'll use option 2 for clarity
            print(f"Detected binary bitcode from bpflifter_cli, converting to text IR...")
            temp_text_ir = lifted_ir_file + ".text.ll"
            run_cmd(["llvm-dis", lifted_ir_file, "-o", temp_text_ir], 
                    f"Convert Program {program_num} bitcode to text IR")
            # Replace the original file with text IR
            import shutil
            shutil.move(temp_text_ir, lifted_ir_file)
        
        # Now optimize (file should be text IR at this point)
        # opt -S reads text IR and outputs text IR
        # However, opt can also read binary and output text with -S
        # But to be safe, we ensure input is text IR first
        run_cmd(["opt", "-O3", "-S", lifted_ir_file, "-o", lifted_ir_file], 
                f"Optimize Program {program_num} IR")
        
        # Verify the file is now text IR (not binary) after optimization
        # If opt -S outputs binary when given binary input, convert it
        try:
            with open(lifted_ir_file, 'rb') as f:
                first_bytes = f.read(10)
                if first_bytes.startswith(b'BC') or first_bytes.startswith(b'\xde\xc0\x17\x0b'):
                    print(f"WARNING: File is still binary after opt -S, converting with llvm-dis...")
                    temp_text_ir = lifted_ir_file + ".text.ll"
                    run_cmd(["llvm-dis", lifted_ir_file, "-o", temp_text_ir], 
                            f"Convert Program {program_num} optimized bitcode to text IR")
                    import shutil
                    shutil.move(temp_text_ir, lifted_ir_file)
        except Exception as e:
            print(f"WARNING: Could not verify file format after optimization: {e}")
        
        # Step 3: Extract relocation info
        do_relocate = gen_reloc_dump(obj_file, prog_temp_dir, program_num)
        map_offset_mapping = os.path.join(prog_temp_dir, "map_offset_mapping")
        print(f"Has relocations: {do_relocate}")
        
        # Step 4: Apply function pass if relocations exist
        # Get script directory for relative paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        func_pass_lib = os.getenv("FUNC_PASS_LIB", 
            os.path.join(script_dir, "llvm_func_pass/build/libfunc_pass.so"))
        if do_relocate and os.path.exists(func_pass_lib):
            # opt without -S outputs bitcode, so we need to use -S to keep text IR format
            run_cmd([
                "opt", "-load", func_pass_lib, f"-load-pass-plugin={func_pass_lib}",
                "-passes=custom-bpf-pass", "-map-config", map_offset_mapping,
                "-S", lifted_ir_file, "-o", lifted_ir_file
            ], f"Remove map globals for Program {program_num}")
        else:
            if not do_relocate:
                print(f"Skipping function pass for Program {program_num} (no relocations found)")
            if not os.path.exists(func_pass_lib):
                print(f"WARNING: Function pass library not found: {func_pass_lib}")
        
        # Step 5: Generate config for this program
        config = generate_config(prog_temp_dir, program_config, program_num)
        
        return config, lifted_ir_file, do_relocate
        
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)

def generate_config(dir, program_config=None, program_num=1):
    """Generate configuration from map_dump and prog_dump files"""
    config = {}
    
    # Read all program names from prog_dump
    prog_dump_path = os.path.join(dir, "prog_dump")
    if os.path.exists(prog_dump_path):
        with open(prog_dump_path, 'r') as f:
            all_progs = [n.strip() for n in f.readlines() if n.strip()]
    else:
        all_progs = []
    config["all_progs"] = all_progs
    
    # Get tailcall config if available
    # For cross-program mode, we need to get tailcalls from the program-specific config
    tailcalls_config = {}
    if program_config:
        # Check for program-specific tailcall config (e.g., program1.tailcalls or program2.tailcalls)
        prog_key = f"program{program_num}"
        if prog_key in program_config and "tailcalls" in program_config[prog_key]:
            tailcalls_config = program_config[prog_key]["tailcalls"]
        # Also check for global tailcalls config (for backward compatibility)
        elif "tailcalls" in program_config:
            tailcalls_config = program_config["tailcalls"]
    
    # Get map_init config if available
    config["map_init"] = []
    if program_config and "map_init" in program_config:
        config["map_init"] = program_config["map_init"]
    
    config["maps"] = []
    map_dump_path = os.path.join(dir, "map_dump")
    if os.path.exists(map_dump_path):
        with open(map_dump_path, 'r') as f:
            for line in f:
                if line.strip():
                    info = line.strip().split(',')
                    map_name = info[0]
                    
                    # Skip .rodata and other non-map sections
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
                        for entry in entries:
                            if entry["function"] not in all_progs:
                                print(f"WARNING: Tailcall function '{entry['function']}' not found in prog_dump")
                        map_entry["tailcall_entries"] = entries
                        print(f"Added {len(entries)} tailcall entries for map '{map_name}'")
                    
                    config["maps"].append(map_entry)
    
    return config

def merge_cross_program_configs(prog1_config, prog2_config, yaml_config, prog1_entry, prog2_entry):
    """Merge configurations from two programs"""
    merged = {}
    
    # Merge program names first (needed for tailcall validation)
    all_progs = list(set(prog1_config.get("all_progs", []) + prog2_config.get("all_progs", [])))
    
    # Get tailcall configs from YAML for both programs
    tailcalls_prog1 = {}
    tailcalls_prog2 = {}
    if yaml_config:
        if "program1" in yaml_config and "tailcalls" in yaml_config["program1"]:
            tailcalls_prog1 = yaml_config["program1"]["tailcalls"]
        if "program2" in yaml_config and "tailcalls" in yaml_config["program2"]:
            tailcalls_prog2 = yaml_config["program2"]["tailcalls"]
    
    # Merge maps with deduplication
    merged_maps = []
    map_names_seen = set()
    
    # Add maps from program 1
    for map1 in prog1_config.get("maps", []):
        map_name = map1["name"]
        if map_name not in map_names_seen:
            # Add tailcall entries if this map has them in prog1 config
            if map1.get("is_prog_array") and map_name in tailcalls_prog1:
                map1["tailcall_entries"] = tailcalls_prog1[map_name]
                # Validate tailcall functions exist
                for entry in map1["tailcall_entries"]:
                    if entry.get("function") and entry["function"] not in all_progs:
                        print(f"WARNING: Tailcall function '{entry['function']}' not found in any program")
            merged_maps.append(map1)
            map_names_seen.add(map_name)
        else:
            # Check if properties match
            existing_map = next((m for m in merged_maps if m["name"] == map_name), None)
            if existing_map:
                if (existing_map["type"] != map1["type"] or
                    existing_map["key_size"] != map1["key_size"] or
                    existing_map["value_size"] != map1["value_size"] or
                    existing_map["max_entries"] != map1["max_entries"]):
                    print(f"WARNING: Map '{map_name}' has conflicting properties between programs. Using first occurrence.")
                # Merge tailcall entries if this is a prog_array
                if existing_map.get("is_prog_array") and map_name in tailcalls_prog1:
                    existing_map["tailcall_entries"] = tailcalls_prog1[map_name]
    
    # Add maps from program 2 that aren't already in merged list
    for map2 in prog2_config.get("maps", []):
        map_name = map2["name"]
        if map_name not in map_names_seen:
            # Add tailcall entries if this map has them in prog2 config
            if map2.get("is_prog_array") and map_name in tailcalls_prog2:
                map2["tailcall_entries"] = tailcalls_prog2[map_name]
                # Validate tailcall functions exist
                for entry in map2["tailcall_entries"]:
                    if entry.get("function") and entry["function"] not in all_progs:
                        print(f"WARNING: Tailcall function '{entry['function']}' not found in any program")
            merged_maps.append(map2)
            map_names_seen.add(map_name)
        else:
            # Map already exists, merge tailcall entries if needed
            existing_map = next((m for m in merged_maps if m["name"] == map_name), None)
            if existing_map and existing_map.get("is_prog_array") and map_name in tailcalls_prog2:
                existing_map["tailcall_entries"] = tailcalls_prog2[map_name]
    
    merged["maps"] = merged_maps
    
    # Merge program names
    merged["all_progs"] = all_progs
    
    # Set program function names
    merged["prog1_func"] = prog1_entry
    merged["prog2_func"] = prog2_entry
    
    # Verify both programs have same type
    global prog1_type, prog2_type
    if prog1_type != prog2_type:
        print(f"WARNING: Program types differ: Program 1 is {prog1_type}, Program 2 is {prog2_type}")
        print(f"Using {prog1_type} as default")
    merged["program_type"] = prog1_type
    
    # Merge map_init from yaml_config if provided
    merged["map_init"] = []
    if yaml_config and "map_init" in yaml_config:
        merged["map_init"] = yaml_config["map_init"]
    
    return merged

def generate_cross_program_code(config, template_path='.', template_filename='draco_cross_prog_template.j2', 
                                output_path='generated_cross_prog.tmpl.c', function_pass_ran=False):
    """Generate cross-program template code"""
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template(template_filename)
    rendered = template.render({
        'maps': config['maps'],
        'prog1_func': config['prog1_func'],
        'prog2_func': config['prog2_func'],
        'program_type': config['program_type'],
        'map_init': config.get('map_init', []),
        'function_pass_ran': function_pass_ran,
        'all_progs': config.get('all_progs', [])
    })
    with open(output_path, 'w') as f:
        f.write(rendered)

# Main execution
if len(sys.argv) < 5:
    print("Usage: generateCrossProgramIR.py <prog1_obj> <prog1_entry> <prog2_obj> <prog2_entry> [program_config.yaml]")
    exit(1)

prog1_obj = sys.argv[1]
prog1_entry = sys.argv[2]
prog2_obj = sys.argv[3]
prog2_entry = sys.argv[4]
program_config_path = sys.argv[5] if len(sys.argv) > 5 else None

# Load program config if provided
program_config = None
if program_config_path and os.path.exists(program_config_path):
    with open(program_config_path, 'r') as f:
        program_config = yaml.safe_load(f)
    print(f"Loaded program config: {program_config_path}")
elif program_config_path:
    print(f"WARNING: Program config file not found: {program_config_path}")

# Override entry functions from YAML if provided
if program_config:
    if "program1" in program_config and "entry_func" in program_config["program1"]:
        prog1_entry = program_config["program1"]["entry_func"]
    if "program2" in program_config and "entry_func" in program_config["program2"]:
        prog2_entry = program_config["program2"]["entry_func"]

print(f"\n=== Cross-Program Analysis ===")
print(f"Program 1: {prog1_obj} -> {prog1_entry}")
print(f"Program 2: {prog2_obj} -> {prog2_entry}")

# Create main temp directory
main_temp_dir = tempfile.mkdtemp()
print(f"Working dir: {main_temp_dir}")

try:
    # Lift Program 1 (pass program_config for tailcall config)
    prog1_config, prog1_ir_file, prog1_pass_ran = lift_single_program(prog1_obj, main_temp_dir, 1, program_config)
    
    # Lift Program 2 (pass program_config for tailcall config)
    prog2_config, prog2_ir_file, prog2_pass_ran = lift_single_program(prog2_obj, main_temp_dir, 2, program_config)
    
    # Merge configurations
    print(f"\n[Merging Configurations]")
    merged_config = merge_cross_program_configs(prog1_config, prog2_config, program_config, 
                                                prog1_entry, prog2_entry)
    print(f"Merged maps: {len(merged_config['maps'])}")
    print(f"Program 1 function: {merged_config['prog1_func']}")
    print(f"Program 2 function: {merged_config['prog2_func']}")
    print(f"Program type: {merged_config['program_type']}")
    
    # Generate template
    print(f"\n[Generating Cross-Program Template]")
    gen_cpp_path = os.path.join(main_temp_dir, "cpp_generated_code.c")
    # Use prog1_pass_ran as indicator (both should be same, but use OR to be safe)
    function_pass_ran = prog1_pass_ran or prog2_pass_ran
    # Get template path (use script directory)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generate_cross_program_code(config=merged_config, 
                                template_path=script_dir, 
                                output_path=gen_cpp_path, 
                                function_pass_ran=function_pass_ran)
    
    if not os.path.exists(gen_cpp_path):
        print(f"ERROR: Template file not written: {gen_cpp_path}")
        exit(1)
    
    # Compile template
    print(f"\n[Compiling Template]")
    klee_include = os.environ.get("KLEE_INCLUDE", "/home/anakin/DRACO-pvt/klee/include")
    clang_cmd = [
        "clang-13", "-target", "bpf", "-DKLEE_VERIFICATION", "-DVERIFY_INTERACTIONS"
    ] + KLEE_BPF_CFLAGS.strip().split() + [
        "-I", klee_include, "-D__USE_VMLINUX__", "-D__TARGET_ARCH_x86",
        "-DBPF_NO_PRESERVE_ACCESS_INDEX", "-Wall", "-Wno-unused-value", "-Wno-unused-variable",
        "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types", "-Wno-unused-function",
        "-fno-discard-value-names", "-fno-builtin", "-O0", "-emit-llvm", "-c", "-g",
        gen_cpp_path, "-o", gen_cpp_path.replace('.c', '.bc')
    ]
    run_cmd(clang_cmd, "Compile template")
    
    # Apply external symbol pass if available
    print(f"\n[Applying External Symbol Pass]")
    ext_pass_lib = os.getenv("EXT_SYM_PASS_LIB")
    if ext_pass_lib and os.path.exists(ext_pass_lib):
        run_cmd(["opt", f"-load-pass-plugin={ext_pass_lib}", "-passes=int-to-ext", 
                gen_cpp_path.replace('.c', '.bc'), "-o", gen_cpp_path.replace('.c', '.bc')], 
                "Ext sym pass", check=False)
    
    # Convert IR files to .bc format for linking
    # Check if files are already bitcode (opt pass may output bitcode) or text IR
    prog1_bc = prog1_ir_file.replace('.ll', '.bc')
    prog2_bc = prog2_ir_file.replace('.ll', '.bc')
    
    # Check if prog1 is already bitcode
    prog1_is_bitcode = False
    try:
        with open(prog1_ir_file, 'rb') as f:
            first_bytes = f.read(10)
            prog1_is_bitcode = first_bytes.startswith(b'BC') or first_bytes.startswith(b'\xde\xc0\x17\x0b')
    except:
        pass
    
    if prog1_is_bitcode:
        # File is already bitcode, just copy/rename it
        import shutil
        shutil.copy2(prog1_ir_file, prog1_bc)
        print(f"Program 1 file is already bitcode, using it directly")
    else:
        # File is text IR, convert to bitcode
        run_cmd(["llvm-as", prog1_ir_file, "-o", prog1_bc], "Convert prog1 IR to bitcode", capture_output=False)
    
    # Check if prog2 is already bitcode
    prog2_is_bitcode = False
    try:
        with open(prog2_ir_file, 'rb') as f:
            first_bytes = f.read(10)
            prog2_is_bitcode = first_bytes.startswith(b'BC') or first_bytes.startswith(b'\xde\xc0\x17\x0b')
    except:
        pass
    
    if prog2_is_bitcode:
        # File is already bitcode, just copy/rename it
        import shutil
        shutil.copy2(prog2_ir_file, prog2_bc)
        print(f"Program 2 file is already bitcode, using it directly")
    else:
        # File is text IR, convert to bitcode
        run_cmd(["llvm-as", prog2_ir_file, "-o", prog2_bc], "Convert prog2 IR to bitcode", capture_output=False)
    
    # Rename conflicting global symbols before linking
    # The function pass creates a global symbol that conflicts when linking multiple programs
    placeholder_symbol = "bpf_map_def_placeholder_and_it_is_completely_useless_stuff_just_to_ensure_that_struct_gets_defined"
    
    print(f"\n[Renaming Conflicting Symbols]")
    import re
    import random
    import string
    
    # Generate unique suffixes for each program
    prog1_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    prog2_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    # Convert bitcode to text IR to rename symbols
    prog1_text = prog1_bc.replace('.bc', '_renamed.ll')
    prog2_text = prog2_bc.replace('.bc', '_renamed.ll')
    
    # Disassemble bitcode to text IR
    run_cmd(["llvm-dis", prog1_bc, "-o", prog1_text], "Disassemble prog1 for symbol renaming", capture_output=False)
    run_cmd(["llvm-dis", prog2_bc, "-o", prog2_text], "Disassemble prog2 for symbol renaming", capture_output=False)
    
    # Rename the placeholder symbol in each program to make it unique
    with open(prog1_text, 'r') as f:
        content = f.read()
    # Replace the symbol name with a unique version for program 1
    new_symbol1 = f"bpf_map_def_placeholder_prog1_{prog1_suffix}"
    content = re.sub(
        r'@' + re.escape(placeholder_symbol) + r'\b',
        '@' + new_symbol1,
        content
    )
    with open(prog1_text, 'w') as f:
        f.write(content)
    print(f"Renamed symbol in prog1 to: {new_symbol1}")
    
    with open(prog2_text, 'r') as f:
        content = f.read()
    # Replace the symbol name with a unique version for program 2
    new_symbol2 = f"bpf_map_def_placeholder_prog2_{prog2_suffix}"
    content = re.sub(
        r'@' + re.escape(placeholder_symbol) + r'\b',
        '@' + new_symbol2,
        content
    )
    with open(prog2_text, 'w') as f:
        f.write(content)
    print(f"Renamed symbol in prog2 to: {new_symbol2}")
    
    # Convert back to bitcode
    prog1_bc_renamed = prog1_bc.replace('.bc', '_renamed.bc')
    prog2_bc_renamed = prog2_bc.replace('.bc', '_renamed.bc')
    run_cmd(["llvm-as", prog1_text, "-o", prog1_bc_renamed], "Reassemble prog1 after renaming", capture_output=False)
    run_cmd(["llvm-as", prog2_text, "-o", prog2_bc_renamed], "Reassemble prog2 after renaming", capture_output=False)
    
    # Use renamed bitcode files for linking
    prog1_bc = prog1_bc_renamed
    prog2_bc = prog2_bc_renamed
    
    # Link all IRs
    print(f"\n[Linking All IRs]")
    # Output should be in the current working directory (where the script was called from)
    # This is typically the example directory (e.g., examples/cross_prog)
    output_dir = os.getcwd()
    final_ir_path = os.path.join(output_dir, "final_linked_ir.bc")
    template_bc = gen_cpp_path.replace('.c', '.bc')
    run_cmd(["llvm-link", template_bc, prog1_bc, prog2_bc, 
             "-o", final_ir_path], "Link all IRs")
    print(f"Output: {final_ir_path}")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

