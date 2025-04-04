# OLETools Secure MCP Server

This project provides a secure microservice using `FastMCP` to analyze Microsoft Office documents (Excel, Word, PowerPoint) and related file types (like XLL add-ins) for potential malicious content using static analysis techniques. It leverages external tools like `oletools`, `XLMMacroDeobfuscator`, and `pefile`.

## Features

*   Analyzes VBA Macros (`olevba`)
*   Detects XLM Macros (`XLMMacroDeobfuscator`, `olevba`)
*   Checks for DDE Links (`msodde`)
*   Extracts embedded OLE Objects (`oleobj`)
*   Extracts IOCs (URLs, IPs, Hashes, Emails) using `iocextract`
*   Designed for integration with systems supporting the MCP protocol (like compatible versions of Claude Desktop).


## Prerequisites
- **Python 3.6+**
- **OLETools**: Install via `pip install oletools`
- **XLMMacroDeobfuscator**: Install via `pip install XLMMacroDeobfuscator`
- **python-magic**: Install via `pip install python-magic-bin` (Windows)
- **iocextract** (optional): Install via `pip install iocextract` for advanced IOC extraction
- **Claude Desktop** application

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/pradeep895/oletools_MCP_claude.git
   cd oletools-mcp-server
   ```
2. **Install Dependencies**:
 ```bash
 pip install -r requirements.txt
 ```
3. Download the "Claude Desktop" application go to the Developer settings and Edit the "claude_desktop_config.json" file and paste content in the configuration.json file.Restart the application.

4. **Run the server**:
 ```bash
 python server.py
  ```
5. Go to "Claude Desktop" application and check for the "hammer symbol" it appeared means MCP tools are available.
. type "analyze_vba_macros in <filepath\example.xlsm>" this will help you to analyze the excel file statically and gave you the findings.
 ```bash
 analyze_vba_macros file_path:"C:\path\to\your\example.xlsm"
 ```

