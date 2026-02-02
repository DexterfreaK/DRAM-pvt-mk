"""
Pipeline wrapper for eBPF verification

Wraps existing tools (generateIR.py, KLEE) via subprocess calls.
"""

import os
import subprocess
import time
from typing import Dict, Any, Optional, Tuple
from .config import get_config
from .utils import get_logger

logger = get_logger("pipeline")


def run_lifting_pipeline(
    object_file: str,
    program_config: Optional[str],
    entry_function: Optional[str],
    intermediate_dir: str,
    debug: bool = False,
    debug_output_file: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Run BPF lifting pipeline by calling generateIR.py.
    
    Args:
        object_file: Path to eBPF object file
        program_config: Path to program_config.yaml (optional)
        entry_function: Entry function name (optional)
        intermediate_dir: Directory for intermediate files
        
    Returns:
        Tuple of (final_ir_path, stdout, stderr)
        
    Raises:
        subprocess.CalledProcessError: If lifting fails
    """
    config = get_config()
    generate_ir_script = config.paths.get("generate_ir")
    
    if not generate_ir_script or not os.path.exists(generate_ir_script):
        raise FileNotFoundError(f"generateIR.py not found at {generate_ir_script}")
    
    # Build command
    cmd = ["python3", generate_ir_script, object_file]
    
    # Add optional arguments
    if entry_function:
        cmd.append(entry_function)
    if program_config:
        cmd.append(program_config)
    
    logger.info(f"Running lifting pipeline: {' '.join(cmd)}")
    
    # Run generateIR.py
    result = subprocess.run(
        cmd,
        cwd=intermediate_dir,
        capture_output=True,
        text=True,
        check=False
    )
    
    if result.returncode != 0:
        logger.error(f"Lifting pipeline failed: {result.stderr}")
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            result.stdout,
            result.stderr
        )
    
    # Find final_linked_ir.bc (generateIR.py outputs it in the same dir as object_file)
    object_dir = os.path.dirname(object_file)
    final_ir_path = os.path.join(object_dir, "final_linked_ir.bc")
    
    if not os.path.exists(final_ir_path):
        # Try in intermediate_dir
        final_ir_path = os.path.join(intermediate_dir, "final_linked_ir.bc")
        if not os.path.exists(final_ir_path):
            raise FileNotFoundError("final_linked_ir.bc not found after lifting")
    
    logger.info(f"Lifting pipeline completed: {final_ir_path}")
    
    # Write debug output if enabled
    if debug and debug_output_file:
        try:
            with open(debug_output_file, 'a') as f:
                f.write("=" * 80 + "\n")
                f.write("LIFTING PIPELINE OUTPUT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Command: {' '.join(cmd)}\n")
                f.write(f"Return code: {result.returncode}\n")
                f.write("\n--- STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)
                f.write("\n\n")
        except Exception as e:
            logger.warning(f"Failed to write debug output: {e}")
    
    return final_ir_path, result.stdout, result.stderr


def run_cross_program_pipeline(
    object1_file: str,
    object2_file: str,
    program_config: str,
    prog1_func: str,
    prog2_func: str,
    intermediate_dir: str,
    debug: bool = False,
    debug_output_file: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Run cross-program lifting pipeline by calling generateCrossProgramIR.py.

    Args:
        object1_file: Path to first eBPF object file
        object2_file: Path to second eBPF object file
        program_config: Path to program_config.yaml
        prog1_func: Entry function name for program 1
        prog2_func: Entry function name for program 2
        intermediate_dir: Directory for intermediate files and output (final_linked_ir.bc)

    Returns:
        Tuple of (final_ir_path, stdout, stderr)
    """
    config = get_config()
    script = config.paths.get("generate_cross_program_ir")
    if not script:
        # Fallback: same dir as generate_ir but generateCrossProgramIR.py
        generate_ir = config.paths.get("generate_ir", "")
        if generate_ir:
            script = os.path.join(os.path.dirname(generate_ir), "generateCrossProgramIR.py")
    if not script or not os.path.exists(script):
        raise FileNotFoundError(
            f"generateCrossProgramIR.py not found at {script}. "
            "Set paths.generate_cross_program_ir in daemon.yaml."
        )

    cmd = [
        "python3", script,
        object1_file, prog1_func,
        object2_file, prog2_func,
        program_config
    ]
    logger.info(f"Running cross-program pipeline: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        cwd=intermediate_dir,
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:
        logger.error(f"Cross-program pipeline failed: {result.stderr}")
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            result.stdout,
            result.stderr
        )

    final_ir_path = os.path.join(intermediate_dir, "final_linked_ir.bc")
    if not os.path.exists(final_ir_path):
        raise FileNotFoundError(
            f"final_linked_ir.bc not found in {intermediate_dir} after cross-program lifting"
        )

    logger.info(f"Cross-program pipeline completed: {final_ir_path}")

    if debug and debug_output_file:
        try:
            with open(debug_output_file, "a") as f:
                f.write("=" * 80 + "\n")
                f.write("CROSS-PROGRAM LIFTING PIPELINE OUTPUT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Command: {' '.join(cmd)}\n")
                f.write(f"Return code: {result.returncode}\n")
                f.write("\n--- STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)
                f.write("\n\n")
        except Exception as e:
            logger.warning(f"Failed to write debug output: {e}")

    return final_ir_path, result.stdout, result.stderr


def run_klee_verification(
    final_ir_path: str,
    constraints_file: str,
    output_dir: str,
    timeout: Optional[int] = None,
    debug: bool = False,
    debug_output_file: Optional[str] = None
) -> Tuple[str, str, str, int]:
    """
    Run KLEE symbolic execution on the lifted IR.
    
    Args:
        final_ir_path: Path to final_linked_ir.bc
        constraints_file: Path to constraints.json
        output_dir: Directory for KLEE output
        timeout: Timeout in seconds (optional)
        
    Returns:
        Tuple of (klee_output_dir, stdout, stderr, return_code)
        
    Raises:
        subprocess.CalledProcessError: If KLEE fails (non-zero return code)
    """
    config = get_config()
    klee_binary = config.paths.get("klee")
    klee_config = config.klee_config
    
    if not klee_binary or not os.path.exists(klee_binary):
        raise FileNotFoundError(f"KLEE binary not found at {klee_binary}")
    
    # Build KLEE command
    cmd = [
        klee_binary,
        "-kdalloc",
        f"-kdalloc-heap-start-address={klee_config.get('heap_start_address', '0x00040000000')}",
        f"-kdalloc-heap-size={klee_config.get('heap_size', 1)}",
        "-libc=uclibc",
        "--external-calls=all",
        "--disable-verify",
        f"-solver-backend={klee_config.get('solver_backend', 'z3')}",
        "-silent-klee-assume=true",
        "--exit-on-error",
        f"-max-memory={klee_config.get('max_memory', 750000)}",
        "-search=dfs",
        "-single-object-resolution=true",
        "-verification=true",
        "-read-set=true",
        "-write-set=true",
        "-map-correlation=true",
        "-restrict-helper-function=true",
        "-enable-map-access-control=true",
        "-enable-packet-constr=true",
        f"-config-file={constraints_file}",
        f"--output-dir={output_dir}",
        final_ir_path
    ]
    
    logger.info(f"Running KLEE: {' '.join(cmd)}")
    
    start_time = time.time()
    
    # Run KLEE
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or klee_config.get('timeout', 300),
            check=False
        )
    except subprocess.TimeoutExpired:
        logger.error(f"KLEE execution timed out after {timeout or klee_config.get('timeout', 300)} seconds")
        raise
    
    duration = time.time() - start_time
    
    # Find KLEE output directory (klee-last symlink or klee-out-N)
    klee_output_dir = output_dir
    klee_last = os.path.join(output_dir, "klee-last")
    if os.path.islink(klee_last):
        klee_output_dir = os.path.realpath(klee_last)
    elif os.path.exists(klee_last):
        klee_output_dir = klee_last
    
    logger.info(f"KLEE execution completed in {duration:.2f}s (return code: {result.returncode})")
    logger.info(f"KLEE output directory: {klee_output_dir}")
    
    if result.returncode != 0:
        logger.warning(f"KLEE returned non-zero exit code: {result.returncode}")
        logger.warning(f"KLEE stderr: {result.stderr[:500]}")
    
    # Write debug output if enabled
    if debug and debug_output_file:
        try:
            with open(debug_output_file, 'a') as f:
                f.write("=" * 80 + "\n")
                f.write("KLEE VERIFICATION OUTPUT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Command: {' '.join(cmd)}\n")
                f.write(f"Return code: {result.returncode}\n")
                f.write(f"Duration: {duration:.2f}s\n")
                f.write("\n--- STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)
                f.write("\n\n")
        except Exception as e:
            logger.warning(f"Failed to write debug output: {e}")
    
    return klee_output_dir, result.stdout, result.stderr, result.returncode


def parse_verification_results(klee_output_dir: str) -> Dict[str, Any]:
    """
    Parse KLEE verification result files.
    
    Args:
        klee_output_dir: Path to KLEE output directory
        
    Returns:
        Dictionary with parsed results:
        {
            "helper_functions": {"valid": bool, "message": str, "restricted_helpers": list},
            "map_access": {"valid": bool, "message": str, "violations": list}
        }
    """
    results = {
        "helper_functions": {
            "valid": True,
            "message": "",
            "restricted_helpers": []
        },
        "map_access": {
            "valid": True,
            "message": "",
            "violations": []
        }
    }
    
    # Parse helperFunc.results
    helper_file = os.path.join(klee_output_dir, "helperFunc.results")
    if os.path.exists(helper_file):
        with open(helper_file, 'r') as f:
            content = f.read()
            if "No use of restricted function detected" in content:
                results["helper_functions"]["valid"] = True
                results["helper_functions"]["message"] = "No use of restricted function detected in any execution path"
            else:
                results["helper_functions"]["valid"] = False
                # Extract restricted helper names
                lines = content.split('\n')
                for line in lines:
                    if "Restriction on use of helper function" in line:
                        # Extract function name
                        if ':"' in line:
                            func_name = line.split(':"')[1].split('"')[0]
                            results["helper_functions"]["restricted_helpers"].append(func_name)
                results["helper_functions"]["message"] = content.strip()
    else:
        logger.warning(f"helperFunc.results not found in {klee_output_dir}")
        results["helper_functions"]["valid"] = False
        results["helper_functions"]["message"] = "helperFunc.results file not found"
    
    # Parse mapAccess.results
    map_file = os.path.join(klee_output_dir, "mapAccess.results")
    if os.path.exists(map_file):
        with open(map_file, 'r') as f:
            content = f.read()
            if "Map Access control : VALID" in content:
                results["map_access"]["valid"] = True
                results["map_access"]["message"] = "Map Access control : VALID"
            else:
                results["map_access"]["valid"] = False
                # Extract violations
                lines = content.split('\n')
                for line in lines:
                    if "No Read Permission" in line or "No Write Permission" in line:
                        results["map_access"]["violations"].append(line.strip())
                results["map_access"]["message"] = content.strip()
    else:
        logger.warning(f"mapAccess.results not found in {klee_output_dir}")
        results["map_access"]["valid"] = False
        results["map_access"]["message"] = "mapAccess.results file not found"
    
    return results


def is_verification_passed(verification_results: Dict[str, Any]) -> bool:
    """
    Determine if verification passed based on results.
    
    Args:
        verification_results: Results from parse_verification_results()
        
    Returns:
        True if both helper_functions and map_access are valid
    """
    helper_valid = verification_results.get("helper_functions", {}).get("valid", False)
    map_valid = verification_results.get("map_access", {}).get("valid", False)
    return helper_valid and map_valid


def parse_klee_statistics(klee_output_dir: str) -> Dict[str, int]:
    """
    Parse KLEE statistics from info file.
    
    Args:
        klee_output_dir: Path to KLEE output directory
        
    Returns:
        Dictionary with statistics:
        {
            "paths_explored": int,
            "total_instructions": int
        }
    """
    stats = {
        "paths_explored": 0,
        "total_instructions": 0
    }
    
    info_file = os.path.join(klee_output_dir, "info")
    if not os.path.exists(info_file):
        logger.warning(f"info file not found in {klee_output_dir}")
        return stats
    
    try:
        with open(info_file, 'r') as f:
            content = f.read()
            
            # Parse explored paths
            # Format: "KLEE: done: explored paths = 23"
            for line in content.split('\n'):
                if 'explored paths =' in line:
                    try:
                        paths = int(line.split('=')[1].strip())
                        stats["paths_explored"] = paths
                    except (ValueError, IndexError):
                        pass
                
                # Parse total instructions
                # Format: "KLEE: done: total instructions = 148713"
                if 'total instructions =' in line:
                    try:
                        instructions = int(line.split('=')[1].strip())
                        stats["total_instructions"] = instructions
                    except (ValueError, IndexError):
                        pass
        
        logger.info(f"Parsed KLEE statistics: {stats}")
    except Exception as e:
        logger.warning(f"Failed to parse KLEE statistics: {e}")
    
    return stats


def collect_output_files(klee_output_dir: str) -> Dict[str, str]:
    """
    Collect paths to all output files in KLEE output directory.
    
    Args:
        klee_output_dir: Path to KLEE output directory
        
    Returns:
        Dictionary mapping file names to full paths
    """
    output_files = {}
    
    important_files = [
        "helperFunc.results",
        "mapAccess.results",
        "info",
        "warnings.txt",
        "messages.txt"
    ]
    
    for filename in important_files:
        filepath = os.path.join(klee_output_dir, filename)
        if os.path.exists(filepath):
            output_files[filename] = filepath
    
    # Also collect .ktest files
    if os.path.exists(klee_output_dir):
        for filename in os.listdir(klee_output_dir):
            if filename.endswith('.ktest'):
                output_files[filename] = os.path.join(klee_output_dir, filename)
    
    return output_files
