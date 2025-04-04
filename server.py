from mcp.server.fastmcp import FastMCP
import subprocess
import json
import os
import pefile  # Added for .XLL analysis
import re

# Define the OLEtools MCP server
mcp = FastMCP("oletools-mcp")

@mcp.tool()
def analyze_vba_macros(file_path: str) -> dict:
    """
    Analyze VBA macros in an Excel file.
    """
    try:
        result = subprocess.run(["olevba", file_path], capture_output=True, text=True, timeout=30)
        return {
            "output": result.stdout if result.stdout else "No VBA macros detected.",
            "error": result.stderr,
            "status": result.returncode
        }
    except FileNotFoundError:
        return {"error": "olevba command not found. Ensure oletools is installed.", "status": -1}
    except subprocess.TimeoutExpired:
        return {"error": "Operation timed out.", "status": -1}
    except Exception as e:
        return {"error": f"Error running analyze_vba_macros: {str(e)}", "status": -1}

@mcp.tool()
def detect_xlm_macros(file_path: str) -> dict:
    """
    Detect and analyze XLM macros using XLMMacroDeobfuscator for .xls files or oletools for other formats.
    """
    try:
        file_extension = os.path.splitext(file_path.lower())[1]

        if file_extension == '.xls':
            result = subprocess.run(
                ["python", "-m", "XLMMacroDeobfuscator.deobfuscator", "-f", file_path, "--start-point", "Sheet1!A1"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and "No XLM macros found" not in result.stdout:
                return {
                    "output": result.stdout if result.stdout else "No XLM macros detected.",
                    "error": result.stderr,
                    "status": result.returncode
                }
            elif result.returncode != 0:
                return {
                    "output": "",
                    "error": f"XLMMacroDeobfuscator failed: {result.stderr}",
                    "status": result.returncode
                }
        result = subprocess.run(
            ["olevba", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            if "XLM macro" in result.stdout.lower():
                return {
                    "output": result.stdout,
                    "error": result.stderr,
                    "status": result.returncode
                }
            return {
                "output": "No XLM macros detected (checked with oletools).",
                "error": result.stderr,
                "status": result.returncode
            }
        else:
            return {
                "output": "",
                "error": f"olevba failed: {result.stderr}",
                "status": result.returncode
            }
    except FileNotFoundError as e:
        return {"error": f"Command not found: {str(e)}. Ensure Python, oletools, and XLMMacroDeobfuscator are installed.", "status": -1}
    except subprocess.TimeoutExpired:
        return {"error": "Operation timed out.", "status": -1}
    except Exception as e:
        return {"error": f"Error running detect_xlm_macros: {str(e)}", "status": -1}

@mcp.tool()
def check_dde_links(file_path: str) -> dict:
    """
    Check for DDE links.
    """
    try:
        result = subprocess.run(["msodde", file_path], capture_output=True, text=True, timeout=30)
        return {
            "output": result.stdout if result.stdout else "No DDE links detected.",
            "error": result.stderr,
            "status": result.returncode
        }
    except FileNotFoundError:
        return {"error": "msodde command not found. Ensure oletools is installed.", "status": -1}
    except subprocess.TimeoutExpired:
        return {"error": "Operation timed out.", "status": -1}
    except Exception as e:
        return {"error": f"Error running check_dde_links: {str(e)}", "status": -1}

@mcp.tool()
def extract_ole_objects(file_path: str) -> dict:
    """
    Extract embedded OLE objects.
    """
    try:
        result = subprocess.run(["oleobj", file_path], capture_output=True, text=True, timeout=30)
        return {
            "output": result.stdout if result.stdout else "No OLE objects detected.",
            "error": result.stderr,
            "status": result.returncode
        }
    except FileNotFoundError:
        return {"error": "oleobj command not found. Ensure oletools is installed.", "status": -1}
    except subprocess.TimeoutExpired:
        return {"error": "Operation timed out.", "status": -1}
    except Exception as e:
        return {"error": f"Error running extract_ole_objects: {str(e)}", "status": -1}

@mcp.tool()
def detect_xll_files(file_path: str) -> dict:
    """
    Analyzes XLL file exports for suspicious functions using pefile.
    """
    try:
        file_extension = os.path.splitext(file_path.lower())[1]
        if file_extension != '.xll':
            return {
                "output": "Not an .XLL file.",
                "error": "",
                "status": 0,
                "suspicious_functions": []
            }

        # Analyze the .XLL file (which is a DLL)
        pe = pefile.PE(file_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return {
                "output": "No export table found in .XLL file.",
                "error": "",
                "status": 0,
                "suspicious_functions": []
            }

        # Extract exported functions
        exported_functions = [entry.name.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols if entry.name]

        # Check for suspicious functions
        suspicious_functions = ['xlAutoOpen', 'xlAutoClose', 'DllMain']
        found_functions = [func for func in suspicious_functions if func in exported_functions]

        if found_functions:
            return {
                "output": f"Suspicious .XLL file detected. Exported functions: {found_functions}",
                "error": "",
                "status": 0,
                "suspicious_functions": found_functions
            }
        return {
            "output": "No suspicious functions found in .XLL file.",
            "error": "",
            "status": 0,
            "suspicious_functions": []
        }
    except FileNotFoundError:
        return {"error": "File not found.", "status": -1, "suspicious_functions": []}
    except pefile.PEFormatError as e:
        return {"error": f"Invalid PE file: {str(e)}", "status": -1, "suspicious_functions": []}
    except Exception as e:
        return {"error": f"Error analyzing .XLL file: {str(e)}", "status": -1, "suspicious_functions": []}

@mcp.tool()
def scan_for_iocs(file_path: str) -> dict:
    """
    Combine outputs to detect IOCs (e.g., URLs, IPs, executables).
    """
    try:
        # Run all tools and collect results
        vba_result = analyze_vba_macros(file_path)
        xlm_result = detect_xlm_macros(file_path)
        dde_result = check_dde_links(file_path)
        ole_result = extract_ole_objects(file_path)
        xll_result = detect_xll_files(file_path)

        # Check for errors in any of the results
        if any(r.get("status", -1) != 0 for r in [vba_result, xlm_result, dde_result, ole_result, xll_result]):
            errors = [r.get("error", "") for r in [vba_result, xlm_result, dde_result, ole_result, xll_result] if r.get("status", -1) != 0]
            return {
                "output": "",
                "iocs": {},
                "error": f"One or more tools failed: {', '.join(errors)}",
                "status": -1
            }

        # Combine outputs
        combined_output = (
            f"VBA Analysis:\n{vba_result['output']}\n\n" +
            f"XLM Analysis:\n{xlm_result['output']}\n\n" +
            f"DDE Links:\n{dde_result['output']}\n\n" +
            f"OLE Objects:\n{ole_result['output']}\n\n" +
            f"XLL Analysis:\n{xll_result['output']}"
        )

        # Refined IOC detection
        iocs = {
            "urls": [line for line in combined_output.splitlines() if any(prot in line.lower() for prot in ["http", "https", "ftp"])],
            "ips": [line for line in combined_output.splitlines() if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line)],
            "executables": [line for line in combined_output.splitlines() if any(ext in line.lower() for ext in [".exe", ".bat", ".cmd"])]
        }

        return {
            "output": combined_output,
            "iocs": {k: v for k, v in iocs.items() if v},  # Only include non-empty IOC lists
            "status": 0
        }
    except Exception as e:
        return {"error": f"Error running scan_for_iocs: {str(e)}", "status": -1}

@mcp.tool()
def classify_malware(file_path: str) -> dict:
    """
    Classify the Excel file as clean or malicious based on analysis.
    """
    try:
        # Run existing tools to gather data
        vba_result = analyze_vba_macros(file_path)
        ioc_result = scan_for_iocs(file_path)

        # Check for errors
        if vba_result.get("status", -1) != 0 or ioc_result.get("status", -1) != 0:
            return {
                "file_path": file_path,
                "is_malicious": False,
                "reasons": ["Analysis failed due to errors"],
                "error": f"VBA: {vba_result.get('error', '')}, IOC: {ioc_result.get('error', '')}",
                "status": -1
            }

        # Extract relevant information
        vba_output = vba_result["output"]
        iocs = ioc_result["iocs"]

        # Classification logic
        is_malicious = False
        reasons = []

        # Check for auto-executable macros
        if "AutoOpen" in vba_output or "AutoExec" in vba_output:
            is_malicious = True
            reasons.append("Auto-executable macro detected (AutoOpen/AutoExec)")

        # Check for IOCs
        if iocs.get("urls"):
            is_malicious = True
            reasons.append(f"Suspicious URLs detected: {iocs['urls']}")
        if iocs.get("ips"):
            is_malicious = True
            reasons.append(f"Suspicious IPs detected: {iocs['ips']}")
        if iocs.get("executables"):
            is_malicious = True
            reasons.append(f"Suspicious executables detected: {iocs['executables']}")

        # If no issues found, mark as clean
        if not reasons:
            reasons.append("No suspicious patterns detected")

        return {
            "file_path": file_path,
            "is_malicious": is_malicious,
            "reasons": reasons,
            "status": 0
        }
    except Exception as e:
        return {"error": f"Error running classify_malware: {str(e)}", "status": -1}

if __name__ == "__main__":
    mcp.run()