# Pando
Pando is a first response, in-depth, practical malware analysis tool providing quick detailed insights on a sample.


## Features

### General Information Reporting
- **Filename & Size**: Reports the filename and size of the analyzed PE.
- **OS & Architecture Detection**: Reports the operating system and architecture (x86 or x64) of the PE .
- **Hash Calculation**: Reports import hash, MD5, SHA1, and SHA256 hashes of the PE.

### Rule-Based Analysis
- **Behavior Based Rule Matching**: Scans the file against a set of ~600 predefined CAPA behavioral rules (loaded from `rules.pkl`)
- **Custom CAPA rule engine**: A fully re-written engine for processing CAPA rules.

### Section Analysis
- **Entropy Calculation**: Calculates the entropy of each section in the PE file and reports packed sections.
- **Obfuscation Detection**: Assesses the level of obfuscation based on the cyclomatic complexity of the code, performed with fastCFG/angr.
- **Section Classification**: Classifies sections into types such as executable, code, data, or other.

### Resource Analysis
- **Resource Extraction**: Extracts and analyzes embedded resources within the PE file.
- **Entropy & Suspicion Level**: Caculates the entropy of resources to determine if they are suspicious, and categorizes them.

### Feature Checks (used within rules)
- **Embedded PE Detection**: Identifies embedded PE files within the binary.
- **Forwarded Export Detection**: Detects forwarded exports within the PE file.
- **Mixed Mode Detection**: Identifies binaries containing both native and managed code.
- **Advanced Pattern Matching**: Detects advanced patterns like loops, tight loops, recursive calls, and stack strings.
- **Indirect Call Detection**: Identifies indirect call instructions. *(which may indicate obfuscation or anti-analysis techniques)*
- **Segment Access Detection**: Checks for access to PEB, FS, or GS segments. *(common in anti-debug and anti-analysis techniques)*
- **Section Detection**: Checks for the presence of a section within the PE file. *(ex. .tls)*
- **String Check**: Detects a specific string, or substring is within the file’s textual content.
- **Bytes Check**: Detects byte patterns within the binary content of the file.
- **Number Check**: Searches for a specific numeric value within the file’s binary content.
- **API Check**: Checks for the presence of specific APIs in the file’s import table.
- **Format Check**: Checks the format of the file *(ex. PE)*
- **Architecture Check**: x86 or x64 check.
- **Operating System Check**: Identifies target operating system for the binary.

## Requirements
- Python 3.x
- Required Libraries: `pefile`, `angr`, `networkx`, `rich`, `argparse`, `logging`, `hashlib`

## Usage
python Pando.py <file_to_scan> [options]  

**-q or --quick** enables quick mode, skipping rules with characteristic checks and cyclomatic complexity analysis for faster but less detailed results.

**-f or --full** enables full mode, which performs a comprehensive analysis of the file, including characteristic checks, cyclomatic complexity analysis, and obfuscation detection.

**-noobf** option skips obfuscation analysis. This option is only applicable in full mode. 

**-v or --verbose** increases rule matching verbosity, reporting where in the address space a rule was matched, *truncating matches with several locations.*
**-vv** enables very verbose mode, which reports all of the rule match locations.
 
Examples:
- To perform a quick scan with minimal output: ```python Pando.py sample.exe --quick```.
- To perform a full scan with detailed findings: ```python Pando.py sample.exe --full -v```.
