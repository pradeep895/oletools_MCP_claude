from mcp.server.fastmcp import FastMCP
import subprocess
import json

# Define the OLEtools MCP server
mcp = FastMCP("oletools-mcp")

# Existing tools (keeping them brief here for space, same as before)
@mcp.tool()
def analyze_vba_macros(file_path: str) -> dict:
    """Analyze VBA macros in an Office document."""
    try:
        result = subprocess.run(["olevba", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def detect_xlm_macros(file_path: str) -> dict:
    """Detect and deobfuscate XLM macros."""
    try:
        result = subprocess.run(["olevba", "--deobfuscate", file_path], capture_output=True, text=True)
        return {"output": result.stdout or "No XLM macros detected.", "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def check_dde_links(file_path: str) -> dict:
    """Check for DDE links in Office documents."""
    try:
        result = subprocess.run(["msodde", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def extract_ole_objects(file_path: str) -> dict:
    """Extract embedded OLE objects."""
    try:
        result = subprocess.run(["oleobj", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def analyze_file_structure(file_path: str) -> dict:
    """Analyze OLE file structure using oleid."""
    try:
        result = subprocess.run(["oleid", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def list_directory_entries(file_path: str) -> dict:
    """List OLE directory entries using oledir."""
    try:
        result = subprocess.run(["oledir", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def map_storage_streams(file_path: str) -> dict:
    """Map OLE storage and streams using olemap."""
    try:
        result = subprocess.run(["olemap", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def extract_timestamps(file_path: str) -> dict:
    """Extract OLE timestamps using oletimes."""
    try:
        result = subprocess.run(["oletimes", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def analyze_rtf(file_path: str) -> dict:
    """Analyze RTF files and extract objects using rtfobj."""
    try:
        result = subprocess.run(["rtfobj", file_path], capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "status": result.returncode}
    except Exception as e:
        return {"error": str(e), "status": -1}

# New tools added
@mcp.tool()
def extract_flash_objects(file_path: str) -> dict:
    """Extract Flash objects (.swf) using pyxswf."""
    try:
        result = subprocess.run(["pyxswf", file_path], capture_output=True, text=True)
        return {
            "output": result.stdout if result.stdout else "No Flash objects detected.",
            "error": result.stderr,
            "status": result.returncode
        }
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def extract_metadata(file_path: str) -> dict:
    """Extract metadata from OLE files using olemeta."""
    try:
        result = subprocess.run(["olemeta", file_path], capture_output=True, text=True)
        return {
            "output": result.stdout,
            "error": result.stderr,
            "status": result.returncode
        }
    except Exception as e:
        return {"error": str(e), "status": -1}

@mcp.tool()
def scan_for_iocs(file_path: str) -> dict:
    """Combine outputs to detect IOCs (e.g., URLs, IPs, executables)."""
    try:
        # Run all tools and collect results
        results = {
            "vba": analyze_vba_macros(file_path),
            "xlm": detect_xlm_macros(file_path),
            "dde": check_dde_links(file_path),
            "ole": extract_ole_objects(file_path),
            "structure": analyze_file_structure(file_path),
            "directory": list_directory_entries(file_path),
            "mapping": map_storage_streams(file_path),
            "timestamps": extract_timestamps(file_path),
            "rtf": analyze_rtf(file_path),
            "flash": extract_flash_objects(file_path),
            "metadata": extract_metadata(file_path)
        }

        # Combine outputs
        combined_output = "\n".join(
            result["output"] for result in results.values() if result["output"]
        )

        # Enhanced IOC detection
        iocs = {
            "urls": [line for line in combined_output.splitlines() if "http" in line.lower()],
            "ips": [line for line in combined_output.splitlines() 
                    if "." in line and len(line.split(".")) == 4 and all(part.isdigit() for part in line.split("."))],
            "executables": [line for line in combined_output.splitlines() 
                          if any(ext in line.lower() for ext in [".exe", ".dll", ".bat", ".swf"])],
            "email": [line for line in combined_output.splitlines() if "@" in line and "." in line]
        }

        return {
            "output": combined_output,
            "iocs": iocs,
            "detailed_results": {k: v for k, v in results.items()},
            "status": 0 if all(r["status"] == 0 for r in results.values()) else -1
        }
    except Exception as e:
        return {"error": str(e), "status": -1}

if __name__ == "__main__":
    mcp.run()