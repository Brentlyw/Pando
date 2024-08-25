import os
import sys
import re
import math
import time
import pickle
import pefile
import argparse
import logging
import hashlib
from pathlib import Path
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.style import Style
from rich.box import ROUNDED
from rich.console import Console
from rich.padding import Padding
from collections import defaultdict
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
try:
    import angr
    import networkx as nx
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

MIN = 1000
MAX = 100000
#Mute angr,cle,pyvex err verbosity
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
console = Console()

def chksec(section_name, pe):
    for section in pe.sections:
        if section.Name.decode().rstrip('\x00').lower() == section_name.lower():
            return True, f"Section '{section_name}' found"
    return False, f"Section '{section_name}' not found"

def chkchar(characteristic, file_path): #Works,needs improvement.
    try:
        pe = pefile.PE(file_path)

        if characteristic == "embedded pe":
            with open(file_path, 'rb') as f:
                content = f.read()
            if b'MZ' in content[2:]:
                return True, [Text.assemble(("Embedded PE detected at offset ", "green"), (f"{content[2:].index(b'MZ') + 2}", "cyan"))]
        elif characteristic == "forwarded export":
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.forwarder:
                        return True, [Text.assemble(("Forwarded export detected: ", "green"), (f"{exp.name.decode()} -> {exp.forwarder.decode()}", "yellow"))]
        elif characteristic == "mixed mode":
            has_native = any(section.Characteristics & 0x20000000 for section in pe.sections)
            has_managed = hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR')
            if has_native and has_managed:
                return True, [Text("Mixed mode (native and managed) code detected", style="green")]
        elif characteristic in ["loop", "tight loop", "recursive call", "calls from", "calls to", 
                                "stack string", "nzxor", "peb access", "fs access", "gs access", 
                                "cross section flow", "indirect call", "call $+5"]:
            if not ANGR_AVAILABLE:
                return False, [Text(f"Angr not available. This should not happen?", style="yellow")] #Rare err but can occur.
            project = angr.Project(file_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast()
            if characteristic in ["loop", "tight loop", "recursive call"]:
                for function in cfg.functions.values():
                    if characteristic == "loop":
                        if any(cfg.graph.has_edge(node, node) for node in function.nodes):
                            return True, [Text.assemble(("Loop detected in function at address ", "green"), (f"0x{function.addr:x}", "cyan"))]
                    elif characteristic == "tight loop":
                        for node in function.nodes:
                            if cfg.graph.has_edge(node, node):
                                block = project.factory.block(node.addr)
                                if len(block.instructions) < 5:
                                    return True, [Text.assemble(("Tight loop detected at address ", "green"), (f"0x{node.addr:x}", "cyan"))]
                    elif characteristic == "recursive call":
                        if any(isinstance(cs, int) and cs == function.addr for cs in function.get_call_sites()): #Change logic not matching always
                            return True, [Text.assemble(("Recursive call detected in function at address ", "green"), (f"0x{function.addr:x}", "cyan"))]
            elif characteristic in ["calls from", "calls to"]:
                for function in cfg.functions.values():
                    if characteristic == "calls from" and function.get_call_sites():
                        return True, [Text.assemble(("Function with outgoing calls detected at address ", "green"), (f"0x{function.addr:x}", "cyan"))]
                    elif characteristic == "calls to" and function.get_predecessors():
                        return True, [Text.assemble(("Function with incoming calls detected at address ", "green"), (f"0x{function.addr:x}", "cyan"))]
            elif characteristic == "stack string":
                for function in cfg.functions.values():
                    instrs = [project.factory.block(addr).capstone.insns for addr in function.block_addrs]
                    instrs = [item for sublist in instrs for item in sublist]#flatten
                    for i in range(len(instrs) - 3):
                        if all(instrs[j].mnemonic == "push" for j in range(i, i+3)) and instrs[i+3].mnemonic == "mov":
                            return True, [Text.assemble(("Potential stack string construction detected at address ", "green"), (f"0x{instrs[i].address:x}", "cyan"))]
            elif characteristic == "nzxor":
                for function in cfg.functions.values():
                    for block in function.blocks:
                        for instr in block.capstone.insns:
                            if instr.mnemonic == "xor" and instr.operands[0].type != instr.operands[1].type:
                                return True, [Text.assemble(("Non-zeroing XOR instruction detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
            elif characteristic in ["peb access", "fs access", "gs access"]:
                for function in cfg.functions.values():
                    for block in function.blocks:
                        for instr in block.capstone.insns:
                            if characteristic == "peb access" and "fs:0x30" in instr.op_str:
                                return True, [Text.assemble(("PEB access detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
                            elif characteristic == "fs access" and "fs:" in instr.op_str:
                                return True, [Text.assemble(("FS segment access detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
                            elif characteristic == "gs access" and "gs:" in instr.op_str:
                                return True, [Text.assemble(("GS segment access detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
            elif characteristic == "cross section flow":
                sections = {section.Name.decode().rstrip('\x00'): (section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize) for section in pe.sections}
                for function in cfg.functions.values():
                    func_section = next((name for name, (start, end) in sections.items() if start <= function.addr < end), None)
                    for call_site in function.get_call_sites():
                        if isinstance(call_site, int):
                            call_section = next((name for name, (start, end) in sections.items() if start <= call_site < end), None)
                            if func_section != call_section:
                                return True, [Text.assemble(("Cross-section call detected from ", "green"), (f"{func_section}", "yellow"), (" to ", "green"), (f"{call_section}", "yellow"), (" at address ", "green"), (f"0x{call_site:x}", "cyan"))]
            elif characteristic == "indirect call":
                for function in cfg.functions.values():
                    for block in function.blocks:
                        for instr in block.capstone.insns:
                            if instr.mnemonic == "call" and instr.op_str[0] in "erq":
                                return True, [Text.assemble(("Indirect call detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
            elif characteristic == "call $+5":
                for function in cfg.functions.values():
                    for block in function.blocks:
                        instrs = list(block.capstone.insns)
                        for i in range(len(instrs) - 1):
                            if instrs[i].mnemonic == "call" and instrs[i].operands[0].type == 2:
                                if instrs[i].operands[0].imm == instrs[i+1].address:
                                    return True, [Text.assemble(("Call $+5 detected at address ", "green"), (f"0x{instrs[i].address:x}", "cyan"))]
        elif characteristic == "unmanaged call":
            with open(file_path, 'rb') as f:
                content = f.read()
            if b'DllImport' in content:
                return True, [Text.assemble(("Potential unmanaged call (P/Invoke) detected at offset ", "green"), (f"{content.index(b'DllImport')}", "cyan"))]
    except Exception as e:
        console.print(f"[bold yellow]Warning: Error checking characteristic '{characteristic}': {str(e)}[/bold yellow]")
    return False, [Text(f"Characteristic '{characteristic}' not found", style="yellow")]

def getfileinfo(file_path):
    file_info = {}
    file_info['filename'] = os.path.basename(file_path)
    file_info['file_size'] = os.path.getsize(file_path)
    try:
        pe = pefile.PE(file_path)
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            file_info['arch'] = 'x64'
        else:
            file_info['arch'] = 'x86'
        file_info['os'] = 'Windows'
        file_info['imphash'] = pe.get_imphash()
    except:
        file_info['arch'] = 'Unknown'
        file_info['os'] = 'Unknown'
        file_info['imphash'] = 'N/A'
    with open(file_path, 'rb') as f:
        data = f.read()
        file_info['md5'] = hashlib.md5(data).hexdigest()
        file_info['sha1'] = hashlib.sha1(data).hexdigest()
        file_info['sha256'] = hashlib.sha256(data).hexdigest()
    return file_info

def showfileinfo(file_info):
    table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
    table.add_column("Attribute", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow")
    table.add_row("Filename", file_info['filename'])
    table.add_row("File Size", f"{file_info['file_size']:,} bytes")
    table.add_row("OS + Architecture", f"{file_info['os']} {file_info['arch']}")
    table.add_row("Import Hash", file_info['imphash'])
    table.add_row("MD5 Hash", file_info['md5'])
    table.add_row("SHA1 Hash", file_info['sha1'])
    table.add_row("SHA256 Hash", file_info['sha256'])
    panel = Panel(table, title="[bold cyan]File Information[/bold cyan]", border_style="bright_magenta", box=ROUNDED)
    console.print(panel)
    
def loadrules(pkl_file):
    with open(pkl_file, 'rb') as file:
        rules_data = pickle.load(file)
    return rules_data

def calcent(data):
    if len(data) == 0:
        return 0.0
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    entropy = 0
    for count in occurrences:
        if count == 0:
            continue
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy

def calccyclo(g):
    ne = g.graph.number_of_edges()
    nn = g.graph.number_of_nodes()
    nc = nx.number_weakly_connected_components(g.graph)
    return ne - nn + 2 * nc

def normscr(score, mi=MIN, ma=MAX):
    ns = (score - mi) / (ma - mi) * 100
    return ns

def getobflvl(ns): #based on the minmax score, might need finetuning, made from samples i tested.
    if ns >= 70:
        return "Very High Obfuscation"
    elif ns >= 50:
        return "High Obfuscation"
    elif ns >= 25:
        return "Moderate Obfuscation"
    elif ns >= 10:
        return "Light Obfuscation"
    elif ns >= 5:
        return "Very Light Obfuscation"
    else:
        return "Not Obfuscated"

def anasec(file_path, skip_obfuscation=False):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        console.print(f"[bold yellow]Warning: {file_path} is not a valid PE file.[/bold yellow]")
        return [], None, None
    section_analysis = []
    complexity_score = 0
    normalized_score = 0
    if ANGR_AVAILABLE and not skip_obfuscation:
        try:
            project = angr.Project(file_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast(normalize=True)
            complexity_score = calccyclo(cfg)
            normalized_score = normscr(complexity_score)
        except Exception as e:
            console.print(f"[bold yellow]Warning: Error in angr analysis: {str(e)}[/bold yellow]")
    total_size = sum(section.SizeOfRawData for section in pe.sections)
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        entropy = section.get_entropy()
        packed_status = entropy > 6.5
        packed_status_text = "Packed" if packed_status else "Not Packed"
        obfuscation_status = getobflvl(normalized_score) if not skip_obfuscation else "N/A"
        size = section.SizeOfRawData
        size_percentage = (size / total_size) * 100
        is_executable = section.Characteristics & 0x20000000
        contains_code = section.Characteristics & 0x00000020
        contains_data = section.Characteristics & 0x00000040
        if is_executable and contains_code:
            section_type = "Executable + Code"
        elif is_executable:
            section_type = "Executable"
        elif contains_data:
            section_type = "Data"
        else:
            section_type = "Other"
        section_analysis.append({
            "name": name,
            "entropy": entropy,
            "packed_status": packed_status_text,
            "obfuscation_status": obfuscation_status,
            "size_percentage": size_percentage,
            "section_type": section_type
        })
    return section_analysis, complexity_score, normalized_score

def anares(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            entropy = calcent(data)
                            size = len(data)
                            if entropy > 7.5:
                                suspicion = "Highly Suspicious"
                                color = "bright_red"
                            elif entropy > 6.5:
                                suspicion = "Suspicious"
                                color = "bright_yellow"
                            else:
                                suspicion = "Normal"
                                color = "green_yellow"
                            resource_type_str = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'Unknown')
                            resources.append({
                                'type': resource_type_str,
                                'name': str(resource_id.name) if hasattr(resource_id, 'name') else str(resource_id.id),
                                'language': pefile.LANG.get(resource_lang.data.lang, 'Unknown'),
                                'sublanguage': pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang),
                                'offset': resource_lang.data.struct.OffsetToData,
                                'size': size,
                                'entropy': entropy,
                                'suspicion': suspicion,
                                'suspicion_color': color
                            })
    return resources

def showresana(resources):
    if not resources:
        return
    table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Name", style="yellow")
    table.add_column("Language", style="magenta")
    table.add_column("Size", style="blue")
    table.add_column("Entropy", style="green")
    table.add_column("Suspicion", style="red")
    for resource in resources:
        suspicion_text = Text(resource['suspicion'], style=resource['suspicion_color'])
        table.add_row(
            resource['type'],
            resource['name'],
            f"{resource['language']} ({resource['sublanguage']})",
            f"{resource['size']:,} bytes",
            f"{resource['entropy']:.2f}",
            suspicion_text
        )
    panel = Panel(table, title="[bold cyan]Resource Analysis[/bold cyan]", border_style="bright_magenta", box=ROUNDED)
    console.print(panel)
        
def showsecana(section_analysis, skip_obfuscation=False):
    table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
    table.add_column("Section Name", style="cyan", no_wrap=True)
    table.add_column("Entropy", style="yellow")
    table.add_column("Packed Status", style="magenta")
    if not skip_obfuscation:
        table.add_column("Obfuscation Status", style="green")
    table.add_column("Size %", style="blue")
    table.add_column("Type", style="bright_yellow")
    for section in section_analysis:
        row = [
            section["name"],
            f"{section['entropy']:.2f}",
            section["packed_status"],
            f"{section['size_percentage']:.2f}%",
            section["section_type"]
        ]
        if not skip_obfuscation:
            row.insert(3, section["obfuscation_status"])
        table.add_row(*row)
    panel = Panel(table, title="[bold cyan]Section Analysis[/bold cyan]", border_style="bright_magenta", box=ROUNDED)
    console.print(panel)
    
def chkfeat(features, file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode):
    if isinstance(features, list):
        results = [chkfeat(feature, file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode) for feature in features]
        matches = [item for sublist in results for item in sublist[1] if sublist[0]]
        return any(r[0] for r in results), matches
    if isinstance(features, dict):
        if 'and' in features:
            results = [chkfeat(sub_feature, file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode) for sub_feature in features['and']]
            matches = [item for sublist in results for item in sublist[1] if sublist[0]]
            return all(r[0] for r in results), matches
        elif 'or' in features:
            results = [chkfeat(sub_feature, file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode) for sub_feature in features['or']]
            matches = [item for sublist in results for item in sublist[1] if sublist[0]]
            return any(r[0] for r in results), matches
        elif 'characteristic' in features:
            return chkchar(features['characteristic'], file_path)
        elif 'section' in features:
            pe = pefile.PE(file_path)
            return chksec(features['section'], pe)
        elif 'optional' in features:
            result, context = chkfeat(features['optional'], file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode)
            return True, context if result else []
        elif 'not' in features:
            result, context = chkfeat(features['not'], file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode)
            return not result, [Text.assemble(("NOT ", "red"), (item, "yellow")) for item in context] if result else []
        elif 'match' in features:
            required_match = features['match']
            if required_match in matched_rules_dict:
                return True, [Text.assemble(("Matched rule ", "green"), (required_match, "yellow"))]
            else:
                return False, []
        elif 'string' in features:
            return chkstr(features['string'].lower(), file_content_text.lower())
        elif 'substring' in features:
            return chksubstr(features['substring'].lower(), file_content_text.lower())
        elif 'bytes' in features:
            return chkbytes(features['bytes'], file_content_binary)
        elif 'number' in features:
            return chknum(features['number'], file_content_binary, very_verbose_mode)
        elif 'api' in features:
            return chkapi(features['api'], file_info)
        elif 'format' in features:
            return chkfmt(features['format'].lower(), file_info)
        elif 'arch' in features:
            return file_info['arch'].lower() == features['arch'].lower(), [Text.assemble(("Architecture is ", "green"), (file_info['arch'], "yellow"))]
        elif 'os' in features:
            return file_info['os'].lower() == features['os'].lower(), [Text.assemble(("Operating system is ", "green"), (file_info['os'], "yellow"))]
    elif isinstance(features, int):
        return chknum(features, file_content_binary, very_verbose_mode)
    return False, []

def chkstr(string_feature, file_content):
    if isinstance(string_feature, str):
        if string_feature.startswith('/') and string_feature.endswith('/i'):
            pattern = string_feature[1:-2]
            matches = list(re.finditer(pattern, file_content, re.IGNORECASE))
            if matches:
                return True, [
                    Text.assemble(
                        ("Matched string ", "green"),
                        (f"'{m.group()}'", "yellow"),
                        (" at offset ", "green"),
                        (f"{m.start()}", "cyan")
                    ) for m in matches
                ]
        else:
            index = file_content.find(string_feature)
            if index != -1:
                return True, [Text.assemble(
                    ("Matched string ", "green"),
                    (f"'{string_feature}'", "yellow"),
                    (" at offset ", "green"),
                    (f"{index}", "cyan")
                )]
    return False, []

def chksubstr(substring_feature, file_content):
    if isinstance(substring_feature, str):
        if substring_feature in file_content:
            return True, f"Substring '{substring_feature}' found"
    return False, None

def chkbytes(bytes_feature, file_content):
    try:
        byte_string = bytes_feature.split('=')[0].strip()
        byte_pattern = bytes.fromhex(byte_string.replace(' ', ''))
        matches = []
        for i in range(len(file_content) - len(byte_pattern) + 1):
            if file_content[i:i+len(byte_pattern)] == byte_pattern:
                matches.append(Text.assemble(
                    ("Matched bytes ", "green"),
                    (f"'{byte_string}'", "yellow"),
                    (" at offset ", "green"),
                    (f"{i}", "cyan")
                ))
        if matches:
            return True, matches
    except ValueError:
        console.print(f"[bold yellow]Warning: Invalid byte pattern: {bytes_feature}[/bold yellow]")
    return False, []

def chknum(number_feature, file_content, very_verbose=False):
    description = None
    if isinstance(number_feature, int):
        number = number_feature
    else:
        if '=' in number_feature:
            number_str, description = number_feature.split('=', 1)
            number_str = number_str.strip()
            description = description.strip()
        else:
            number_str = number_feature.strip()
        if number_str.startswith("0x"):
            number = int(number_str, 16)
        else:
            number = int(number_str)
    
    number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='little')
    matches = defaultdict(list)
    
    for i in range(len(file_content) - len(number_bytes) + 1):
        if file_content[i:i+len(number_bytes)] == number_bytes:
            matches[number].append(i)
    
    if matches:
        formatted_matches = []
        for num, offsets in matches.items():
            offset_str = ','.join(map(str, offsets[:3]))
            if len(offsets) > 3 and not very_verbose:
                offset_str += f"... (+{len(offsets) - 3} more)"
            elif very_verbose:
                offset_str = ','.join(map(str, offsets))
            
            match_text = Text()
            match_text.append("Matched number ", style="green")
            match_text.append(f"{hex(num)}", style="yellow")
            match_text.append(" at offset(s) ", style="green")
            match_text.append(offset_str, style="cyan")
            if description:
                match_text.append(f" ({description})", style="magenta")
            
            formatted_matches.append(match_text)
        return True, formatted_matches
    return False, []
    
    if matches:
        formatted_matches = []
        for num, offsets in matches.items():
            match_description = f"Matched number {hex(num)} at offset(s) {','.join(map(str, offsets))}"
            if description:
                match_description += f" ({description})"
            formatted_matches.append(match_description)
        return True, formatted_matches
    return False, []

def chkapi(api_feature, file_info):
    api_feature = api_feature.lower()
    api_name = api_feature.split('.')[-1]
    base_api_name = api_name.rstrip('aw')
    normalized_imports = [imp.lower() for imp in file_info.get('imports', [])]
    matches = []
    for imported_api in normalized_imports:
        imported_api_base = imported_api.rstrip('aw')
        if imported_api == api_name or imported_api_base == base_api_name:
            match_text = Text()
            match_text.append("Matched API ", style="green")
            match_text.append(f"'{api_feature}'", style="yellow")
            match_text.append(" as ", style="green")
            match_text.append(f"'{imported_api}'", style="cyan")
            match_text.append(" in import table", style="green")
            matches.append(match_text)
    if '::' in api_feature:
        for imported_api in normalized_imports:
            if imported_api == api_name:
                match_text = Text()
                match_text.append("Matched .NET API ", style="green")
                match_text.append(f"'{api_feature}'", style="yellow")
                match_text.append(" as ", style="green")
                match_text.append(f"'{imported_api}'", style="cyan")
                match_text.append(" in import table", style="green")
                matches.append(match_text)
    if matches:
        return True, matches
    return False, []

def chkfmt(format_feature, file_info):
    if file_info['format'] == format_feature:
        return True, f"File format '{format_feature}' matched"
    return False, None

def parsepefile(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())
        arch = 'x86'
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = 'amd64'
        os_type = 'windows' if arch in ['x86', 'amd64'] else 'unknown'
        return {
            'sections': [section.Name.decode().rstrip('\x00') for section in pe.sections],
            'imports': imports,
            'exports': [export.name.decode() if export.name else '' for export in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],
            'arch': arch,
            'os': os_type,
            'format': 'pe'
        }
    except pefile.PEFormatError:
        console.print(f"[bold yellow]Warning: {file_path} is not a valid PE file.[/bold yellow]")
        return {'format': 'unknown', 'imports': [], 'arch': 'unknown', 'os': 'unknown'}

def chkrule(rule, file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode):
    if 'features' not in rule:
        return False, []
    try:
        match, findings = chkfeat(rule['features'], file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode)
        return match, findings
    except Exception as e:
        pass
        return False, []

def scanfile(file_path, rules, quick_mode=False, verbose_mode=False, very_verbose_mode=False):
    try:
        with open(file_path, 'rb') as f:
            file_content_binary = f.read()
        with open(file_path, 'r', errors='ignore') as f:
            file_content_text = f.read()
    except IOError:
        console.print(f"[bold red]Error: Unable to read file '{file_path}'.[/bold red]")
        return []

    file_info = parsepefile(file_path)
    
    matched_rules = []
    matched_rules_dict = {}
    
    for rule in rules:
        if quick_mode and 'characteristic' in str(rule['rule'].get('features', '')):
            continue
        match, findings = chkrule(rule['rule'], file_content_binary, file_content_text, file_info, matched_rules_dict, file_path, very_verbose_mode)
        if match:
            rule['rule']['_match_findings'] = findings
            matched_rules.append(rule['rule'])

    return matched_rules

def fmtrulename(name):
    name_parts = name.split()
    name_parts[0] = name_parts[0].capitalize()
    formatted_name = " ".join(name_parts)
    if "via" in name_parts:
        via_index = name_parts.index("via")
        formatted_name = " ".join(name_parts[:via_index]) + " (" + " ".join(name_parts[via_index:]) + ")"
    return formatted_name

def main():
    try:
        parser = argparse.ArgumentParser(description="Scan a file with Pando.")
        parser.add_argument("file_to_scan", help="The file to scan")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-q", "--quick", action="store_true", help="Enable quick mode (skip characteristic checks and cyclomatic complexity)")
        group.add_argument("-f", "--full", action="store_true", help="Enable full mode (run all checks)")
        parser.add_argument("-noobf", action="store_true", help="Skip obfuscation analysis (only applicable in full mode)")
        parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity (use -vv for very verbose)")
        args = parser.parse_args()

        file_to_scan = args.file_to_scan
        quick_mode = args.quick
        skip_obfuscation = args.noobf if args.full else True
        verbose_mode = args.verbose > 0
        very_verbose_mode = args.verbose > 1

        if args.noobf and args.quick:
            console.print("[bold yellow]Warning: -noobf flag is ignored in quick mode[/bold yellow]")

        rules_file = os.path.join(os.path.dirname(__file__), 'rules.pkl')

        if not os.path.exists(file_to_scan):
            console.print(f"[bold red]Error: File '{file_to_scan}' not found.[/bold red]")
            sys.exit(1)

        if not os.path.exists(rules_file):
            console.print(f"[bold red]Error: Rules file '{rules_file}' not found.[/bold red]")
            sys.exit(1)

        rules = loadrules(rules_file)

        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.fields[time_taken]:.2f}s"),
        ) as progress:
            overall_task = progress.add_task("[cyan]Analyzing file...", total=100, time_taken=0)

            progress.update(overall_task, advance=10, description="Loading rules...")
            progress.update(overall_task, time_taken=time.time() - start_time)
            
            progress.update(overall_task, advance=10, description="Gathering file metadata...")
            file_info = getfileinfo(file_to_scan)
            progress.update(overall_task, time_taken=time.time() - start_time)

            scan_description = "Matching rules..."
            if quick_mode:
                scan_description += " (quick mode)"
            else:
                scan_description += " (full mode)"
            progress.update(overall_task, advance=20, description=scan_description)
            matched_rules = scanfile(file_to_scan, rules, quick_mode, verbose_mode, very_verbose_mode)
            progress.update(overall_task, time_taken=time.time() - start_time)

            section_description = "Analyzing sections..."
            if not quick_mode and not skip_obfuscation:
                section_description += " (including obfuscation analysis)"
            progress.update(overall_task, advance=30, description=section_description)
            section_analysis, complexity_score, normalized_score = anasec(file_to_scan, quick_mode or skip_obfuscation)
            progress.update(overall_task, time_taken=time.time() - start_time)

            progress.update(overall_task, advance=20, description="Analyzing resources...")
            pe = pefile.PE(file_to_scan)
            resources = anares(pe)
            progress.update(overall_task, time_taken=time.time() - start_time)

            progress.update(overall_task, advance=10, description="Generating final report...")
            progress.update(overall_task, time_taken=time.time() - start_time)

        total_time = time.time() - start_time
        console.clear()
        showfileinfo(file_info)

        if matched_rules:
            if verbose_mode:
                table = Table(box=None, expand=True, show_header=False, show_edge=False)
                table.add_column("Rule", style="cyan", no_wrap=True)
                table.add_column("Findings", style="yellow", overflow="fold")

                for i, rule in enumerate(sorted(matched_rules, key=lambda r: r['meta']['name'])):
                    if i > 0:

                        table.add_row("", "", style=Style(color="magenta"))
                    
                    rule_name = Text(fmtrulename(rule['meta']['name']), style="cyan")
                    findings = rule.get('_match_findings', 'No detailed findings available')

                    if isinstance(findings, list):
                        formatted_findings = Text()
                        for j, finding in enumerate(findings):
                            if isinstance(finding, Text):
                                formatted_findings.append(finding)
                            else:
                                formatted_findings.append(Text(finding, style="yellow"))
                            if j < len(findings) - 1:  
                                formatted_findings.append("\n")
                    else:
                        formatted_findings = Text(str(findings), style="yellow")
                    
                    table.add_row(rule_name, formatted_findings)

                console.print(Panel(table, title="[bold cyan]Matched Rules[/bold cyan]", border_style="bright_magenta", expand=False))
            else:
                formatted_rule_names = [
                    f"[green]>>[/green] {fmtrulename(rule['meta']['name'])}"
                    for rule in sorted(matched_rules, key=lambda r: r['meta']['name'])
                ]
                rule_names_text = "\n".join(formatted_rule_names)

                panel = Panel(
                    Padding(rule_names_text, (1, 2)),
                    title="[bold cyan]Matched Rules[/bold cyan]",
                    title_align="center",
                    border_style="bright_magenta",
                )
                console.print(panel)
        else:
            console.print(Panel("[bold red]No rules matched.[/bold red]", title="Scan Result", border_style="red"))
        
        showsecana(section_analysis, quick_mode or skip_obfuscation)
        if resources:
            showresana(resources)
    except Exception as e:
        console.print(f"[bold red]An error occurred: {str(e)}[/bold red]")
        import traceback
        console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
