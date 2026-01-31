"""IDA Pro MCP Library Opener

This module provides functionality to automatically open library files in IDA Pro
and start the MCP plugin without user interaction.

Usage:
    This script is called by IDA with -S parameter to auto-start MCP after loading.
"""

import os
import sys
import glob
import subprocess
import tempfile
from typing import Optional, List, Tuple

# Common processor types for IDA
PROCESSOR_TYPES = {
    # Windows PE
    ".dll": "metapc",
    ".exe": "metapc",
    ".sys": "metapc",
    # Linux ELF
    ".so": "metapc",  # Usually x86/x64, but could be ARM
    # macOS
    ".dylib": "metapc",
    # Generic
    ".bin": "metapc",
}

# Architecture detection based on file header
def detect_architecture(filepath: str) -> Tuple[str, int]:
    """Detect the architecture of a binary file.
    
    Returns:
        Tuple of (processor_type, bitness)
        processor_type: IDA processor name (metapc, arm, mips, etc.)
        bitness: 32 or 64
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(64)
        
        # Check for PE (Windows)
        if header[:2] == b'MZ':
            # Read PE header offset
            pe_offset = int.from_bytes(header[0x3C:0x40], 'little')
            f = open(filepath, 'rb')
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig == b'PE\x00\x00':
                machine = int.from_bytes(f.read(2), 'little')
                f.close()
                # Machine types
                if machine == 0x8664:  # AMD64
                    return ("metapc", 64)
                elif machine == 0x14c:  # i386
                    return ("metapc", 32)
                elif machine == 0xaa64:  # ARM64
                    return ("arm", 64)
                elif machine == 0x1c0:  # ARM
                    return ("arm", 32)
            f.close()
        
        # Check for ELF (Linux/Unix)
        elif header[:4] == b'\x7fELF':
            elf_class = header[4]  # 1 = 32-bit, 2 = 64-bit
            machine = int.from_bytes(header[18:20], 'little')
            bitness = 64 if elf_class == 2 else 32
            
            # Machine types
            if machine == 0x3E:  # x86-64
                return ("metapc", 64)
            elif machine == 0x03:  # x86
                return ("metapc", 32)
            elif machine == 0xB7:  # AArch64
                return ("arm", 64)
            elif machine == 0x28:  # ARM
                return ("arm", 32)
            elif machine == 0x08:  # MIPS
                return ("mips", bitness)
        
        # Check for Mach-O (macOS)
        elif header[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',  # 32-bit
                            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):  # 64-bit
            is_64 = header[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
            # CPU type is at offset 4
            cpu_type = int.from_bytes(header[4:8], 'little')
            if cpu_type & 0x1000000:  # 64-bit flag
                is_64 = True
            cpu_type &= 0xFFFFFF
            
            if cpu_type == 7:  # x86
                return ("metapc", 64 if is_64 else 32)
            elif cpu_type == 12:  # ARM
                return ("arm", 64 if is_64 else 32)
        
    except Exception:
        pass
    
    # Default to x64
    return ("metapc", 64)


def find_library(name: str, search_dirs: Optional[List[str]] = None) -> Optional[str]:
    """Search for a library file in the given directories.
    
    Args:
        name: Library name (with or without extension)
        search_dirs: List of directories to search (default: current dir and subdirs)
    
    Returns:
        Full path to the library file, or None if not found
    """
    if search_dirs is None:
        search_dirs = ["."]
    
    # Common library extensions
    extensions = ["", ".dll", ".so", ".dylib", ".exe", ".sys"]
    
    for search_dir in search_dirs:
        # Search in directory and subdirectories
        for root, dirs, files in os.walk(search_dir):
            for ext in extensions:
                target = name + ext if not name.endswith(ext) else name
                target_lower = target.lower()
                
                for f in files:
                    if f.lower() == target_lower:
                        return os.path.join(root, f)
    
    return None


def get_ida_path() -> Optional[str]:
    """Get the path to IDA Pro executable."""
    # Try common locations
    if sys.platform == 'win32':
        common_paths = [
            os.path.join(os.environ.get('PROGRAMFILES', ''), 'IDA Pro *', 'ida64.exe'),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'IDA Pro *', 'ida64.exe'),
            r"C:\Program Files\IDA Pro *\ida64.exe",
            r"D:\*\IDA*\ida64.exe",
        ]
        for pattern in common_paths:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
    else:
        # Linux/macOS
        common_paths = [
            "/opt/ida*/ida64",
            "/usr/local/ida*/ida64",
            os.path.expanduser("~/ida*/ida64"),
        ]
        for pattern in common_paths:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
    
    return None


def create_autostart_script() -> str:
    """Create a temporary IDAPython script that auto-starts MCP.
    
    Returns:
        Path to the temporary script file
    """
    # Note: The script runs with -S parameter, which means it runs BEFORE
    # the database is fully loaded. We need to use UI_Hooks to wait for
    # the database to be ready.
    script_content = '''# Auto-start MCP plugin after IDA loads the binary
# This script is executed via IDA's -S parameter

import idaapi
import ida_auto
import idc

print("[MCP AutoStart] Script loaded")

def start_mcp_plugin():
    """Start MCP plugin after auto-analysis completes."""
    print("[MCP AutoStart] Waiting for auto-analysis...")
    # Wait for auto-analysis to complete
    ida_auto.auto_wait()
    print("[MCP AutoStart] Auto-analysis complete, starting MCP plugin...")
    
    # Try to run MCP plugin
    try:
        result = idaapi.run_plugin("MCP", 0)
        if result:
            print("[MCP AutoStart] MCP plugin started successfully")
        else:
            print("[MCP AutoStart] MCP plugin returned False")
    except Exception as e:
        print(f"[MCP AutoStart] Failed to start MCP plugin: {e}")

class MCPAutoStarter(idaapi.UI_Hooks):
    """UI Hooks to start MCP after database is ready."""
    
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.started = False
    
    def ready_to_run(self):
        """Called when IDA UI is ready and database is loaded."""
        if not self.started:
            self.started = True
            print("[MCP AutoStart] UI ready, scheduling MCP start...")
            # Use execute_sync to run in the main thread
            idaapi.execute_sync(start_mcp_plugin, idaapi.MFF_FAST)
        return 0

# Install hooks
print("[MCP AutoStart] Installing UI hooks...")
mcp_hooks = MCPAutoStarter()
mcp_hooks.hook()
print("[MCP AutoStart] UI hooks installed, waiting for database load...")
'''
    
    # Create temp file in a location that IDA can access
    # Use the system temp directory
    fd, path = tempfile.mkstemp(suffix='.py', prefix='ida_mcp_autostart_')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(script_content)
    
    print(f"[MCP] Created autostart script: {path}")
    return path


def open_library_in_ida(
    library_path: str,
    ida_path: Optional[str] = None,
    auto_start_mcp: bool = True,
) -> bool:
    """Open a library file in IDA Pro with automatic analysis.
    
    Args:
        library_path: Path to the library file
        ida_path: Path to IDA executable (auto-detected if None)
        auto_start_mcp: Whether to auto-start MCP plugin
    
    Returns:
        True if IDA was started successfully
    """
    if not os.path.exists(library_path):
        print(f"[MCP] Library not found: {library_path}")
        return False
    
    # Get IDA path
    if ida_path is None:
        ida_path = get_ida_path()
        if ida_path is None:
            print("[MCP] IDA Pro not found. Please specify the path.")
            return False
    
    # Verify IDA path exists
    if not os.path.exists(ida_path):
        print(f"[MCP] IDA executable not found at: {ida_path}")
        return False
    
    # Detect architecture
    processor, bitness = detect_architecture(library_path)
    
    # Choose ida or ida64 based on bitness
    # Note: IDA 9.x uses a single executable that handles both 32-bit and 64-bit binaries
    # So we only need to adjust for older IDA versions (8.x and earlier)
    original_ida_path = ida_path
    adjusted_ida_path = None
    
    if sys.platform == 'win32':
        if bitness == 32 and ida_path.endswith('ida64.exe'):
            adjusted_ida_path = ida_path.replace('ida64.exe', 'ida.exe')
        elif bitness == 64 and ida_path.endswith('ida.exe') and not ida_path.endswith('ida64.exe'):
            adjusted_ida_path = ida_path.replace('ida.exe', 'ida64.exe')
    else:
        # Linux/macOS
        if bitness == 32 and ida_path.endswith('64'):
            adjusted_ida_path = ida_path[:-2]  # Remove '64'
        elif bitness == 64 and not ida_path.endswith('64'):
            adjusted_ida_path = ida_path + '64'
    
    # Only use adjusted path if it exists, otherwise use original
    # This handles IDA 9.x which uses a single executable
    if adjusted_ida_path and os.path.exists(adjusted_ida_path):
        ida_path = adjusted_ida_path
        print(f"[MCP] Using adjusted IDA path for {bitness}-bit: {ida_path}")
    else:
        if adjusted_ida_path:
            print(f"[MCP] Adjusted IDA path not found: {adjusted_ida_path}, using original: {original_ida_path}")
        # Keep original ida_path
    
    # Build command line
    # Note: IDA command line options:
    # -A: Autonomous mode (no dialogs)
    # -B: Batch mode (implies -A, creates .idb and exits)
    # -c: Create new database (don't load existing .idb)
    # -p<processor>: Processor type (e.g., -pmetapc for x86)
    # -S<script>: Run script after loading
    #
    # For PE files, IDA auto-detects the processor, so we don't need -p
    # The -T option is for text files, not binary processor type
    # Add auto-start script if requested
    autostart_script = None
    if auto_start_mcp:
        autostart_script = create_autostart_script()
    
    # Get absolute path for library
    library_abs_path = os.path.abspath(library_path)
    
    print(f"[MCP] Opening library: {library_path}")
    print(f"[MCP] Architecture: {processor} {bitness}-bit")
    print(f"[MCP] IDA path: {ida_path}")
    
    try:
        # Start IDA in background
        if sys.platform == 'win32':
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            
            # Build command list for Windows
            # Note: On Windows, we need to handle paths with spaces carefully
            cmd = [ida_path, "-A", "-c"]
            if autostart_script:
                # -S parameter: script path must be quoted if it contains spaces
                cmd.append(f'-S"{autostart_script}"')
            cmd.append(library_abs_path)
            
            print(f"[MCP] Command: {cmd}")
            
            # On Windows, use shell=False with proper quoting
            subprocess.Popen(
                cmd,
                creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            # Unix: build command list
            cmd = [ida_path, "-A", "-c"]
            if autostart_script:
                cmd.append(f"-S{autostart_script}")
            cmd.append(library_abs_path)
            
            print(f"[MCP] Command: {cmd}")
            
            subprocess.Popen(
                cmd,
                start_new_session=True,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        
        return True
    except Exception as e:
        print(f"[MCP] Failed to start IDA: {e}")
        import traceback
        traceback.print_exc()
        return False


# For command-line usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Open library in IDA Pro with MCP")
    parser.add_argument("library", help="Library file path or name to search")
    parser.add_argument("--search-dir", "-d", action="append", help="Directory to search")
    parser.add_argument("--ida-path", "-i", help="Path to IDA executable")
    parser.add_argument("--no-mcp", action="store_true", help="Don't auto-start MCP")
    
    args = parser.parse_args()
    
    # Find library if not a direct path
    if os.path.exists(args.library):
        library_path = args.library
    else:
        library_path = find_library(args.library, args.search_dir)
        if library_path is None:
            print(f"Library not found: {args.library}")
            sys.exit(1)
    
    # Open in IDA
    success = open_library_in_ida(
        library_path,
        ida_path=args.ida_path,
        auto_start_mcp=not args.no_mcp,
    )
    
    sys.exit(0 if success else 1)
