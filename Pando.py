import os
import sys
import re
import math
import time
import pickle
import argparse
import logging
import hashlib
import traceback
from collections import defaultdict
import pefile
import networkx as nx
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich.box import ROUNDED
from rich.padding import Padding
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import concurrent.futures
import threading
try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

MIN, MAX = 1000, 100000
console = Console()

class LogCaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []
    def emit(self, record):
        self.records.append(self.format(record))

def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    log_capture = LogCaptureHandler()
    log_capture.setLevel(logging.WARNING)
    log_capture.setFormatter(logging.Formatter('%(levelname)s | %(name)s | %(message)s'))
    root.addHandler(log_capture)
    return log_capture

def chksec(section_name, pe):
    for section in pe.sections:
        if section.Name.decode().rstrip('\x00').lower() == section_name.lower():
            return True, f"Section '{section_name}' found"
    return False, f"Section '{section_name}' not found"

def chkchar(characteristic, file_path, required_count=1):
    count, findings = 0, []
    try:
        pe = pefile.PE(file_path)
        if characteristic == "embedded pe":
            with open(file_path, 'rb') as f:
                content = f.read()
            if b'MZ' in content[2:]:
                offset = content[2:].index(b'MZ') + 2
                return True, [Text.assemble(("Embedded PE detected at offset ", "green"), (f"{offset}", "cyan"))]
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
        elif characteristic.startswith("count(characteristic("):
            inner_char = characteristic[len("count(characteristic("):-1]
            if not ANGR_AVAILABLE:
                return False, [Text(f"Angr not available for counting '{inner_char}'", style="yellow")]
            project = angr.Project(file_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast()
            for func in cfg.functions.values():
                for block in func.blocks:
                    for instr in block.capstone.insns:
                        if inner_char == "nzxor" and instr.mnemonic == "xor" and instr.operands[0].type != instr.operands[1].type:
                            count +=1
            return count >= required_count, [Text(f"Count for {inner_char}: {count}")]
        elif characteristic in ["loop", "tight loop", "recursive call", "calls from", "calls to", 
                                "stack string", "nzxor", "peb access", "fs access", "gs access", 
                                "cross section flow", "indirect call", "call $+5"]:
            if not ANGR_AVAILABLE:
                return False, [Text(f"Angr not available for characteristic '{characteristic}'", style="yellow")]
            project = angr.Project(file_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast()
            if characteristic == "loop":
                for func in cfg.functions.values():
                    if any(cfg.graph.has_edge(node, node) for node in func.nodes):
                        return True, [Text.assemble(("Loop detected in function at address ", "green"), (f"0x{func.addr:x}", "cyan"))]
            elif characteristic == "tight loop":
                for func in cfg.functions.values():
                    for node in func.nodes:
                        if cfg.graph.has_edge(node, node):
                            block = project.factory.block(node.addr)
                            if len(block.capstone.insns) < 5:
                                return True, [Text.assemble(("Tight loop detected at address ", "green"), (f"0x{node.addr:x}", "cyan"))]
            elif characteristic == "recursive call":
                for func in cfg.functions.values():
                    if func.addr in [cs for cs in func.get_call_sites() if isinstance(cs, int)]:
                        return True, [Text.assemble(("Recursive call detected in function at address ", "green"), (f"0x{func.addr:x}", "cyan"))]
            elif characteristic in ["calls from", "calls to"]:
                for func in cfg.functions.values():
                    if (characteristic == "calls from" and func.get_call_sites()) or (characteristic == "calls to" and func.get_predecessors()):
                        return True, [Text.assemble((f"Function with {'outgoing' if characteristic == 'calls from' else 'incoming'} calls detected at address ", "green"), (f"0x{func.addr:x}", "cyan"))]
            elif characteristic == "stack string":
                for func in cfg.functions.values():
                    instrs = [instr for block in func.blocks for instr in block.capstone.insns]
                    for i in range(len(instrs)-3):
                        if all(instrs[j].mnemonic == "push" for j in range(i, i+3)) and instrs[i+3].mnemonic == "mov":
                            return True, [Text.assemble(("Potential stack string construction detected at address ", "green"), (f"0x{instrs[i].address:x}", "cyan"))]
            elif characteristic == "nzxor":
                for func in cfg.functions.values():
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            if instr.mnemonic == "xor" and instr.operands[0].type != instr.operands[1].type:
                                count +=1
                return count >=1, [Text(f"nzxor occurrences: {count}")]
            elif characteristic in ["peb access", "fs access", "gs access"]:
                for func in cfg.functions.values():
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            if (characteristic == "peb access" and "fs:0x30" in instr.op_str) or \
                               (characteristic == "fs access" and "fs:" in instr.op_str) or \
                               (characteristic == "gs access" and "gs:" in instr.op_str):
                                return True, [Text.assemble((f"{characteristic.upper()} access detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
            elif characteristic == "cross section flow":
                sections = {s.Name.decode().rstrip('\x00'): (s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections}
                for func in cfg.functions.values():
                    func_sec = next((name for name, (start, end) in sections.items() if start <= func.addr < end), None)
                    for cs in func.get_call_sites():
                        if isinstance(cs, int):
                            cs_sec = next((name for name, (start, end) in sections.items() if start <= cs < end), None)
                            if func_sec and cs_sec and func_sec != cs_sec:
                                return True, [Text.assemble(("Cross-section call detected from ", "green"), (f"{func_sec}", "yellow"), (" to ", "green"), (f"{cs_sec}", "yellow"), (" at address ", "green"), (f"0x{cs:x}", "cyan"))]
            elif characteristic == "indirect call":
                for func in cfg.functions.values():
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            if instr.mnemonic == "call" and instr.op_str[0] in "erq":
                                return True, [Text.assemble(("Indirect call detected at address ", "green"), (f"0x{instr.address:x}", "cyan"))]
            elif characteristic == "call $+5":
                for func in cfg.functions.values():
                    for block in func.blocks:
                        instrs = list(block.capstone.insns)
                        for i in range(len(instrs)-1):
                            if instrs[i].mnemonic == "call" and instrs[i].operands[0].type == 2 and instrs[i].operands[0].imm == instrs[i+1].address:
                                return True, [Text.assemble(("Call $+5 detected at address ", "green"), (f"0x{instrs[i].address:x}", "cyan"))]
        elif characteristic == "unmanaged call":
            with open(file_path, 'rb') as f:
                content = f.read()
            if b'DllImport' in content:
                offset = content.index(b'DllImport')
                return True, [Text.assemble(("Potential unmanaged call (P/Invoke) detected at offset ", "green"), (f"{offset}", "cyan"))]
    except Exception:
        return False, [Text(f"Characteristic '{characteristic}' not found", style="yellow")]
    return False, [Text(f"Characteristic '{characteristic}' not found", style="yellow")]

def getfileinfo(file_path):
    info = {
        'filename': os.path.basename(file_path),
        'file_size': f"{os.path.getsize(file_path) / 1024:.2f} KB"
    }
    try:
        pe = pefile.PE(file_path)
        info['arch'] = 'x64' if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else 'x86'
        info['os'] = 'Windows'
        info['imphash'] = pe.get_imphash()
    except:
        info.update({'arch': 'Unknown', 'os': 'Unknown', 'imphash': 'N/A'})
    with open(file_path, 'rb') as f:
        data = f.read()
    info.update({
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    })
    return info

def showfileinfo(info):
    table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
    
    # Add columns with headers 'Attribute' and 'Value'
    table.add_column("Attribute", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    
    # Add individual fields
    table.add_row("Filename", str(info.get("filename", "")))
    table.add_row("File Size", str(info.get("file_size", "")))
    
    # Combine 'OS' and 'Architecture' for "OS + Architecture"
    os_arch = f"{info.get('os', 'Unknown')} + {info.get('arch', 'Unknown')}"
    table.add_row("OS + Architecture", os_arch)
    
    # Continue with other hashes
    table.add_row("Import Hash", str(info.get("imphash", "N/A")))
    table.add_row("MD5 Hash", str(info.get("md5", "N/A")))
    table.add_row("SHA1 Hash", str(info.get("sha1", "N/A")))
    table.add_row("SHA256 Hash", str(info.get("sha256", "N/A")))
    
    # Display the table
    console.print(Panel(table, title="[bold cyan]File Information[/bold cyan]", border_style="bright_magenta", box=ROUNDED))


def loadrules(pkl_file):
    import shutil
    with open(pkl_file, 'rb') as f:
        rules = pickle.load(f)
    # Backup the original rules.pkl
    backup_file = pkl_file + '.bak'
    shutil.copy(pkl_file, backup_file)
    # Assign levels based on dependencies
    rule_dict = {}
    for rule in rules:
        name = rule['rule']['meta']['name']
        deps = ruledeps(rule['rule'])
        rule_dict[name] = {'rule': rule['rule'], 'deps': deps, 'level': None}
    deleted_rules = assignrulelvls(rule_dict)
    if deleted_rules:
        console.print(f"[bold yellow]The following rules have missing dependencies and will be deleted:[/bold yellow]")
        for name in deleted_rules:
            console.print(f"- {name}")
        confirm = input("Do you want to proceed with deleting these rules? (y/n): ").lower()
        if confirm != 'y':
            console.print("[bold red]Aborting operation. No changes made to the rules file.[/bold red]")
            sys.exit(1)
    # Save the cleaned-up rules back to pkl_file
    cleaned_rules = [info for info in rule_dict.values()]
    with open(pkl_file, 'wb') as f:
        pickle.dump(cleaned_rules, f)
    # Return rules sorted by level
    sorted_rules = sorted(cleaned_rules, key=lambda x: x['level'])
    return sorted_rules



def ruledeps(rule):
    deps = set()
    def extract_matches(features):
        if isinstance(features, list):
            for feat in features:
                extract_matches(feat)
        elif isinstance(features, dict):
            for key, value in features.items():
                if key == 'match':
                    deps.add(value)
                else:
                    extract_matches(value)
    extract_matches(rule.get('features', {}))
    return deps


def assignrulelvls(rule_dict):
    deleted_rules = []
    changed = True
    while changed:
        changed = False
        for name in list(rule_dict.keys()):
            info = rule_dict[name]
            if info['level'] is None:
                if not info['deps']:
                    info['level'] = 0
                    changed = True
                else:
                    dep_levels = []
                    unresolved_deps = []
                    for dep in info['deps']:
                        if dep in rule_dict:
                            dep_level = rule_dict[dep]['level']
                            if dep_level is not None:
                                dep_levels.append(dep_level)
                        else:
                            unresolved_deps.append(dep)
                    if unresolved_deps:
                        # Remove this rule due to missing dependencies
                        console.print(f"[bold yellow]Warning: Rule '{name}' has missing dependencies: {', '.join(unresolved_deps)}. It will be deleted.[/bold yellow]")
                        del rule_dict[name]
                        deleted_rules.append(name)
                        changed = True
                        break  # Restart the loop since rule_dict changed
                    elif len(dep_levels) == len(info['deps']):
                        # All dependencies have levels assigned
                        info['level'] = max(dep_levels) + 1
                        changed = True
    return deleted_rules





def calcent(data):
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] +=1
    entropy = -sum((count/len(data)) * math.log2(count) for count in freq.values() if count)
    return entropy

def calccyclo(cfg):
    g = cfg.graph
    ne, nn = g.number_of_edges(), g.number_of_nodes()
    nc = nx.number_weakly_connected_components(g)
    return ne - nn + 2 * nc

def normscr(score, mi=MIN, ma=MAX):
    return (score - mi) / (ma - mi) * 100

def getobflvl(ns):
    if ns >= 70:
        return "Very High Obfuscation"
    elif ns >= 50:
        return "High Obfuscation"
    elif ns >= 25:
        return "Moderate Obfuscation"
    elif ns >= 10:
        return "Light Obfuscation"
    elif ns >=5:
        return "Very Light Obfuscation"
    return "Not Obfuscated"

def anasec(file_path, skip_obfuscation=False, progress=None, step_size=0):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        console.print(f"[bold yellow]Warning: {file_path} is not a valid PE file.[/bold yellow]")
        return [], None, None
    section_analysis, complexity, norm = [], 0, 0
    if ANGR_AVAILABLE and not skip_obfuscation:
        try:
            project = angr.Project(file_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast(normalize=True)
            complexity = calccyclo(cfg)
            norm = normscr(complexity)
        except Exception as e:
            console.print(f"[bold yellow]Warning: Error in angr analysis: {str(e)}[/bold yellow]")
    for s in pe.sections:
        name = s.Name.decode().rstrip('\x00')
        entropy = s.get_entropy()
        packed = "Packed" if entropy > 6.5 else "Not Packed"
        obf = getobflvl(norm) if not skip_obfuscation else "N/A"
        # Use the maximum of SizeOfRawData and Misc_VirtualSize
        size_in_bytes = max(s.SizeOfRawData, s.Misc_VirtualSize)
        flags = s.Characteristics
        typ = ("Executable + Code" if (flags & 0x20000000 and flags & 0x20) else
               "Executable" if (flags & 0x20000000) else
               "Data" if (flags & 0x40) else "Other")
        section_analysis.append({
            "name": name,
            "entropy": entropy,
            "packed_status": packed,
            "obfuscation_status": obf,
            "size_in_bytes": size_in_bytes,
            "section_type": typ
        })
        if progress and step_size:
            task_id = progress.tasks[0].id  # Retrieve task ID
            progress.advance(task_id, advance=step_size)  # Advance progress
    return section_analysis, complexity, norm



def anares(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(rt, 'directory'):
                for rid in rt.directory.entries:
                    if hasattr(rid, 'directory'):
                        for lang in rid.directory.entries:
                            data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                            entropy, size = calcent(data), len(data)
                            if entropy >7.5:
                                suspicion, color = "Highly Suspicious", "bright_red"
                            elif entropy >6.5:
                                suspicion, color = "Suspicious", "bright_yellow"
                            else:
                                suspicion, color = "Normal", "green_yellow"
                            rt_str = pefile.RESOURCE_TYPE.get(rt.struct.Id, 'Unknown')
                            resources.append({
                                'type': rt_str,
                                'name': str(rid.name) if hasattr(rid, 'name') else str(rid.id),
                                'language': pefile.LANG.get(lang.data.lang, 'Unknown'),
                                'sublanguage': pefile.get_sublang_name_for_lang(lang.data.lang, lang.data.sublang),
                                'offset': lang.data.struct.OffsetToData,
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
    for col in ["Type", "Name", "Language", "Size", "Entropy", "Suspicion"]:
        table.add_column(col, style={
            "Type":"cyan",
            "Name":"yellow",
            "Language":"magenta",
            "Size":"blue",
            "Entropy":"green",
            "Suspicion":"red"
        }[col], no_wrap=True if col=="Type" else False)
    for res in resources:
        suspicion = Text(res['suspicion'], style=res['suspicion_color'])
        table.add_row(
            res['type'],
            res['name'],
            f"{res['language']} ({res['sublanguage']})",
            f"{res['size']:,} bytes",
            f"{res['entropy']:.2f}",
            suspicion
        )
    console.print(Panel(table, title="[bold cyan]Resource Analysis[/bold cyan]", border_style="bright_magenta", box=ROUNDED))

def showsecana(sec, skip_obf=False):
    table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
    headers = ["Section Name", "Entropy", "Packed Status"] + ([] if skip_obf else ["Obfuscation Status"]) + ["Size", "Type"]
    
    # Add columns with appropriate styles
    for h in headers:
        style_map = {
            "Section Name": "cyan",
            "Entropy": "yellow",
            "Packed Status": "magenta",
            "Obfuscation Status": "green",
            "Size": "dodger_blue3",  # Changed from 'blue' to 'dodger_blue3'
            "Type": "bright_yellow"
        }
        table.add_column(h, style=style_map.get(h, "white"), no_wrap=True if h == "Section Name" else False)
    
    # Add rows with section data
    for s in sec:
        row = [
            s.get("name", "N/A"),
            f"{s.get('entropy', 0.0):.2f}",
            s.get("packed_status", "N/A")
        ]
        if not skip_obf:
            row.append(s.get("obfuscation_status", "N/A"))
        size_in_bytes = s.get("size_in_bytes", 0)
        size_str = readablesize(size_in_bytes)
        row += [
            size_str,
            s.get("section_type", "N/A")
        ]
        table.add_row(*row)
    
    # Display the table
    console.print(Panel(table, title="[bold cyan]Section Analysis[/bold cyan]", border_style="bright_magenta", box=ROUNDED))



def readablesize(size, decimal_places=2):
    if size == 0:
        return '0 B'
    size = float(size)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0:
            return f"{size:.{decimal_places}f} {unit}"
        size /= 1024.0
    return f"{size:.{decimal_places}f} PB"


def chkfeat(features, bin_content, text_content, info, matched_rules, path, very_verbose):
    if isinstance(features, list):
        res, matches = False, []
        for feat in features:
            r, m = chkfeat(feat, bin_content, text_content, info, matched_rules, path, very_verbose)
            res = res or r
            matches.extend(m)
        return res, matches
    if isinstance(features, dict):
        if 'and' in features:
            res, matches = True, []
            for feat in features['and']:
                r, m = chkfeat(feat, bin_content, text_content, info, matched_rules, path, very_verbose)
                res = res and r
                if not res:
                    break  # Short-circuit evaluation
                matches.extend(m)
            return res, matches
        if 'or' in features:
            res, matches = False, []
            for feat in features['or']:
                r, m = chkfeat(feat, bin_content, text_content, info, matched_rules, path, very_verbose)
                if r:
                    res = True
                    matches.extend(m)
                    break  # Short-circuit evaluation
            return res, matches
        if 'not' in features:
            r, m = chkfeat(features['not'], bin_content, text_content, info, matched_rules, path, very_verbose)
            if r:
                findings = [Text.assemble(("NOT ", "red"), (str(item), "yellow")) for item in m]
                return not r, findings
            else:
                return True, []

        if 'optional' in features:
            r, m = chkfeat(features['optional'], bin_content, text_content, info, matched_rules, path, very_verbose)
            return True, m if r else (True, [])
        if 'match' in features:
            matched_rule_name = features['match']
            if matched_rule_name in matched_rules:
                return True, [Text.assemble(("Matched rule ", "green"), (matched_rule_name, "yellow"))]
            else:
                return False, []
        if 'characteristic' in features:
            return chkchar(features['characteristic'], path)
        if 'section' in features:
            pe = pefile.PE(path)
            return chksec(features['section'], pe)
        if 'string' in features:
            return chkstr(features['string'].lower(), text_content.lower())
        if 'substring' in features:
            return chksubstr(features['substring'].lower(), text_content.lower())
        if 'bytes' in features:
            return chkbytes(features['bytes'], bin_content)
        if 'number' in features:
            return chknum(features['number'], bin_content, very_verbose)
        if 'api' in features:
            return chkapi(features['api'], info)
        if 'export' in features:
            return chkexport(features['export'], info)
        if 'import' in features:
            return chkimport(features['import'], info)
        if 'instruction' in features:
            return chkinstruction(features['instruction'], path)
        if 'mnemonic' in features:
            return chkmnemonic(features['mnemonic'], path)
        if 'offset' in features:
            return chkoffset(features['offset'], path)
        if 'class' in features:
            return chkclass(features['class'], info)
        if 'property/read' in features:
            return chkproperty(features['property/read'], info)
        if 'arch' in features:
            return info['arch'].lower() == features['arch'].lower(), [Text.assemble(("Architecture is ", "green"), (info['arch'], "yellow"))]
        if 'os' in features:
            return info['os'].lower() == features['os'].lower(), [Text.assemble(("Operating system is ", "green"), (info['os'], "yellow"))]
        if 'format' in features:
            return chkformat(features['format'].lower(), info)
    if isinstance(features, int):
        return chknum(features, bin_content, very_verbose)
    return False, []


def chkstr(s_feat, text):
    if isinstance(s_feat, str):
        if s_feat.startswith('/') and s_feat.endswith('/i'):
            pattern = s_feat[1:-2]
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                return True, [Text.assemble(("Matched string ", "green"), (f"'{m.group()}'", "yellow"), (" at offset ", "green"), (f"{m.start()}", "cyan")) for m in matches]
        else:
            index = text.find(s_feat)
            if index != -1:
                return True, [Text.assemble(("Matched string ", "green"), (f"'{s_feat}'", "yellow"), (" at offset ", "green"), (f"{index}", "cyan"))]
    return False, []

def chksubstr(sub, text):
    if sub in text:
        return True, [f"Substring '{sub}' found"]
    return False, []

def chkbytes(b_feat, bin_content):
    try:
        byte_str, *_ = b_feat.split('=')
        pattern = bytes.fromhex(byte_str.replace(' ', ''))
        matches = [i for i in range(len(bin_content)-len(pattern)+1) if bin_content[i:i+len(pattern)] == pattern]
        if matches:
            return True, [Text.assemble(("Matched bytes ", "green"), (f"'{byte_str}'", "yellow"), (" at offset ", "green"), (f"{i}", "cyan")) for i in matches[:3]]
    except ValueError:
        console.print(f"[bold yellow]Warning: Invalid byte pattern: {b_feat}[/bold yellow]")
    return False, []

def chknum(n_feat, bin_content, verbose):
    desc = None
    if isinstance(n_feat, int):
        num = n_feat
    else:
        if '=' in n_feat:
            num_str, desc = map(str.strip, n_feat.split('=',1))
        else:
            num_str = n_feat.strip()
        num = int(num_str, 16) if num_str.startswith("0x") else int(num_str)
    num_bytes = num.to_bytes((num.bit_length() +7)//8 or 1, byteorder='little')
    matches = [i for i in range(len(bin_content)-len(num_bytes)+1) if bin_content[i:i+len(num_bytes)] == num_bytes]
    if matches:
        offsets = matches if verbose else matches[:3]
        if len(matches) >3 and not verbose:
            offsets = offsets + [f"... (+{len(matches)-3} more)"]
        return True, [Text.assemble(("Matched number ", "green"), (f"{hex(num)}", "yellow"), (" at offset(s) ", "green"), (','.join(map(str, offsets)), "cyan"), (f" ({desc})", "magenta") if desc else "")]
    return False, []

def chkapi(api_feat, info):
    api_feat = api_feat.lower()
    api_name = api_feat.split('.')[-1]
    base_api = api_name.rstrip('aw')
    imports = [imp.lower() for imp in info.get('imports', [])]
    matches = []
    for imp in imports:
        imp_base = imp.rstrip('aw')
        if imp == api_name or imp_base == base_api:
            matches.append(Text.assemble(("Matched API ", "green"), (f"'{api_feat}'", "yellow"), (" as ", "green"), (f"'{imp}'", "cyan"), (" in import table", "green")))
    if '::' in api_feat:
        for imp in imports:
            if imp == api_name:
                matches.append(Text.assemble(("Matched .NET API ", "green"), (f"'{api_feat}'", "yellow"), (" as ", "green"), (f"'{imp}'", "cyan"), (" in import table", "green")))
    return (bool(matches), matches) if matches else (False, [])

def chkexport(exp_feat, info):
    exports = [e.lower() for e in info.get('exports', [])]
    matches = [Text.assemble(("Matched export ", "green"), (f"'{exp}'", "yellow")) for exp in exp_feat if exp.lower() in exports]
    return (bool(matches), matches) if matches else (False, [])

def chkimport(imp_feat, info):
    imports = [imp.lower() for imp in info.get('imports', [])]
    matches = [Text.assemble(("Matched import ", "green"), (f"'{imp}'", "yellow")) for imp in imp_feat if imp.lower() in imports]
    return (bool(matches), matches) if matches else (False, [])

def chkinstruction(instr_feats, path):
    try:
        project = angr.Project(path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        for func in cfg.functions.values():
            for block in func.blocks:
                for instr in block.capstone.insns:
                    if all(getattr(instr, k) == v for k, v in instr_feats.items()):
                        return True, [Text.assemble((f"Instruction {instr.mnemonic} matched at ", "green"), (f"0x{instr.address:x}", "cyan"))]
    except:
        pass
    return False, []

def chkmnemonic(mnemonic_feats, path):
    try:
        project = angr.Project(path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        for func in cfg.functions.values():
            for block in func.blocks:
                for instr in block.capstone.insns:
                    if instr.mnemonic == mnemonic_feats:
                        return True, [Text.assemble(("Mnemonic ", "green"), (f"'{mnemonic_feats}'", "yellow"), (" found at ", "green"), (f"0x{instr.address:x}", "cyan"))]
    except:
        pass
    return False, []

def chkoffset(offset_feat, path):
    try:
        pe = pefile.PE(path)
        for s in pe.sections:
            if s.VirtualAddress <= offset_feat < s.VirtualAddress + s.Misc_VirtualSize:
                return True, [f"Offset {hex(offset_feat)} found in section {s.Name.decode().rstrip(chr(0))}"]
    except:
        pass
    return False, []

def chkclass(cls_feat, info):
    classes = [cls.lower() for cls in info.get('classes', [])]
    matches = [Text.assemble(("Matched class ", "green"), (f"'{cls}'", "yellow")) for cls in cls_feat if cls.lower() in classes]
    return (bool(matches), matches) if matches else (False, [])

def chkproperty(prop_feat, info):
    props = [prop.lower() for prop in info.get('properties', [])]
    matches = [Text.assemble(("Matched property ", "green"), (f"'{prop}'", "yellow")) for prop in prop_feat if prop.lower() in props]
    return (bool(matches), matches) if matches else (False, [])

def chkformat(fmt_feat, info):
    if info.get('format', '').lower() == fmt_feat:
        return True, [f"File format '{fmt_feat}' matched"]
    return False, []

def parsepefile(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = [imp.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.name]
        exports = [exp.name.decode() if exp.name else '' for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []
        arch = 'amd64' if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else 'i386'
        os_type = 'Windows' if arch in ['i386', 'amd64'] else 'unknown'
        fmt = 'dotnet' if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') else 'pe'
    except pefile.PEFormatError:
        imports, exports, arch, os_type, fmt = [], [], 'unknown', 'unknown', 'unknown'
    with open(file_path, 'rb') as f:
        data = f.read()
    return {
        'sections': [s.Name.decode().rstrip('\x00') for s in pe.sections] if 'pe' in locals() else [],
        'imports': imports,
        'exports': exports,
        'arch': arch,
        'os': os_type,
        'format': fmt,
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'classes': [],
        'properties': []
    }

def chkrule(rule, bin_content, text_content, info, matched_rules, path, very_verbose):
    if 'features' not in rule:
        return False, []
    try:
        match, findings = chkfeat(rule['features'], bin_content, text_content, info, matched_rules, path, very_verbose)
        return match, findings
    except Exception as e:
        console.print(f"[bold yellow]Warning: Error in rule '{rule['meta']['name']}': {e}[/bold yellow]")
        return False, []


def scanfile(file_path, rules, quick, verbose, very_verbose, progress=None, step_size=0):
    try:
        bin_content = open(file_path, 'rb').read()
        text_content = open(file_path, 'r', errors='ignore').read()
    except IOError:
        console.print(f"[bold red]Error: Unable to read file '{file_path}'.[/bold red]")
        return []
    info = parsepefile(file_path)
    matched_rules = set()
    matched_rules_lock = threading.Lock()
    matched = []
    # Organize rules by levels
    max_level = max(rule['level'] for rule in rules)
    for level in range(max_level + 1):
        level_rules = [rule for rule in rules if rule['level'] == level]
        if level == 0:
            # Process Level 0 rules in parallel
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(process_rule, rule, bin_content, text_content, info, matched_rules, matched_rules_lock, file_path, very_verbose): rule for rule in level_rules}
                for future in concurrent.futures.as_completed(futures):
                    rule = futures[future]
                    try:
                        r, f = future.result()
                        if r:
                            rule['rule']['_match_findings'] = f
                            matched.append(rule['rule'])
                            with matched_rules_lock:
                                matched_rules.add(rule['rule']['meta']['name'])
                    except Exception as exc:
                        console.print(f"[bold yellow]Warning: Rule '{rule['rule']['meta']['name']}' generated an exception: {exc}[/bold yellow]")
        else:
            # Process higher-level rules sequentially
            for rule in level_rules:
                r, f = process_rule(rule, bin_content, text_content, info, matched_rules, matched_rules_lock, file_path, very_verbose)
                if r:
                    rule['rule']['_match_findings'] = f
                    matched.append(rule['rule'])
                    with matched_rules_lock:
                        matched_rules.add(rule['rule']['meta']['name'])
        if progress and step_size:
            task_id = progress.tasks[0].id  # Retrieve task ID
            progress.advance(task_id, advance=step_size)
    return matched

def fmtrulename(name):
    parts = name.split()
    parts[0] = parts[0].capitalize()
    if "via" in parts:
        idx = parts.index("via")
        parts = parts[:idx] + ["(" + " ".join(parts[idx:]) + ")"]
    return " ".join(parts)

def process_rule(rule_info, bin_content, text_content, info, matched_rules, matched_rules_lock, file_path, very_verbose):
    rule = rule_info['rule']
    r, f = chkrule(rule, bin_content, text_content, info, matched_rules, file_path, very_verbose)
    if r:
        with matched_rules_lock:
            matched_rules.add(rule['meta']['name'])
    return r, f

def main():
    try:
        log_capture = setup_logging()
        parser = argparse.ArgumentParser(description="Scan a file with Pando.")
        parser.add_argument("file_to_scan", help="The file to scan")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-q", "--quick", action="store_true", help="Enable quick mode (skip characteristic checks and cyclomatic complexity)")
        group.add_argument("-f", "--full", action="store_true", help="Enable full mode (run all checks)")
        parser.add_argument("-noobf", action="store_true", help="Skip obfuscation analysis (only applicable in full mode)")
        parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity (use -vv for very verbose)")
        args = parser.parse_args()
        file_to_scan = args.file_to_scan
        quick = args.quick
        skip_obf = args.noobf or args.quick
        verbose, very_verbose = args.verbose > 0, args.verbose > 1
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
        start = time.time()
        total_rules = len(rules)
        step_size_rule = 60 / total_rules if total_rules > 0 else 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.fields[time_taken]:.2f}s")
        ) as progress:
            task = progress.add_task("[cyan]Scanning file...", total=100, time_taken=0)
            progress.update(task, description="Loading rules...")
            progress.advance(task, advance=5)
            progress.update(task, description="Gathering file metadata...")
            file_info = getfileinfo(file_to_scan)
            progress.advance(task, advance=10)
            desc = "Matching rules... (quick mode)" if quick else "Matching rules... (full mode)"
            progress.update(task, description=desc)
            matched_rules = scanfile(file_to_scan, rules, quick, verbose, very_verbose, progress, step_size_rule)
            time.sleep(0.1)
            progress.advance(task, advance=30)
            sec_desc = "Analyzing sections... (including obfuscation analysis)" if not quick and not skip_obf else "Analyzing sections..."
            progress.update(task, description=sec_desc)
            section_analysis, complexity, norm = anasec(
                file_to_scan,
                skip_obfuscation=skip_obf,
                progress=progress,
                step_size=0.5
            )
            progress.advance(task, advance=20)
            progress.update(task, description="Analyzing resources...")
            pe = pefile.PE(file_to_scan)
            resources = anares(pe)
            progress.advance(task, advance=20)
            progress.update(task, description="Generating final report...")
            progress.advance(task, advance=10)
        total_time = time.time()-start
        console.clear()
        showfileinfo(file_info)
        if matched_rules:
            if verbose:
                table = Table(box=None, expand=True, show_header=False, show_edge=False)
                table.add_column("Rule", style="cyan", no_wrap=True)
                table.add_column("Findings", style="yellow", overflow="fold")
                for i, rule in enumerate(sorted(matched_rules, key=lambda r: r['meta']['name'])):
                    if i > 0:
                        table.add_row("", "", style=Style(color="magenta"))
                    name = Text(fmtrulename(rule['meta']['name']), style="cyan")
                    findings = rule.get('_match_findings', 'No detailed findings available')
                    if isinstance(findings, list):
                        formatted = Text()
                        for f in findings:
                            if not isinstance(f, Text):
                                f = Text(str(f), "yellow")
                            formatted += f
                            formatted += "\n"
                        findings = formatted
                    else:
                        findings = Text(str(findings), "yellow")
                    table.add_row(name, findings)
                console.print(Panel(table, title="[bold cyan]Matched Rules[/bold cyan]", border_style="bright_magenta", expand=False))
            else:
                names = "\n".join([f"[green]>>[/green] {fmtrulename(r['meta']['name'])}" for r in sorted(matched_rules, key=lambda r: r['meta']['name'])])
                console.print(Panel(Padding(names, (1,2)), title="[bold cyan]Matched Rules[/bold cyan]", title_align="center", border_style="bright_magenta"))
        else:
            console.print(Panel("[bold red]No rules matched.[/bold red]", title="Scan Result", border_style="red"))
        showsecana(section_analysis, skip_obf)
        if resources:
            showresana(resources)
        if log_capture.records:
            findings = []
            for log in log_capture.records:
                if "indirect jump" in log.lower():
                    match = re.search(r'Address 0x([0-9A-Fa-f]+)', log)
                    if match:
                        addr = match.group(1)
                        findings.append(f"Indirect jumps at address 0x{addr}")
                elif "operation adc" in log.lower():
                    findings.append("Unsupported ADC operation detected")
                else:
                    findings.append(log)
            if findings:
                table = Table(box=ROUNDED, border_style="bright_magenta", expand=True)
                table.add_column("Warning", style="red")
                for f in findings:
                    table.add_row(f)
                console.print(Panel(table, title="[bold red]Scanner Warnings[/bold red]", border_style="bright_magenta", box=ROUNDED))
    except Exception as e:
        console.print(f"[bold red]An error occurred: {str(e)}[/bold red]")
        console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
