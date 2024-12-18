#!/bin/bash
# --- AMDYara.py ---  

import os
import re

import hashlib
import magic
import time 
import json
import gzip
import argparse
import yara
from collections import Counter
from datetime import datetime
from text_color import TextColors
from lxml import etree

t = TextColors
DATE = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')

GEN_RULES = 'yara-rules/genRules/'
RULES_COMPILE_DIR = 'compile-rules/'
RULES_COMPILE = 'compile-rules/compiled.json'
BLACKLIST_STRING = './xml/strings.xml'
WHITELIST_STRING = 'dbs/'
RELEVANT_EXTENSIONS = ['.exe', '.bat', '.scr', '.sh', '.pdf', '.py', '.dll', '.app', '.class', 
                       '.jar', '.docx', '.js', '.xls', '.xlsb', '.xlsx', '.vb', 'vbe', '.vbs', 
                       '.pif',  '.msi', '.xls', '.lnk', '.ps', '.ps1', '.rtf', '.jpeg', '.jpg', 
                       '.bmp', '.zip', '.tar', '.rar', '.gif', '.sys', '.php', '.cmd']

FORMAT_RULES = '''rule {0} {{
    meta:
        des = "{1}"
        author = "{2}"
        date = "{3}"    
    strings:
{4}
    condition:
        {5}
}}
'''

def log(mes_type, message):
    print(f'{t.blue}[{mes_type}]: {message}{t.end}')

def log_error(mes_type, message):
    print(f'{t.red}[{mes_type}]: {message}{t.end}')

def get_files(target):
    if os.path.isfile(target):
        yield target 
    else:
        for dirpath, _, filenames in os.walk(target):
            for file in filenames:
                yara_path = os.path.join(dirpath, file)
                yield yara_path

def load(filename):
    file = gzip.GzipFile(filename, 'rb')
    object = json.loads(file.read())
    file.close()
    return object

# ----- GENERAL OPTIONS ------
def file_details(file):
    log('INFO', f'Detail file {file}')
    try:
        # File size
        print(f'[+] File size: {os.path.getsize(file)} bytes')
        
        # File hash
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()   
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        
        print(f"[+] MD5: {format(md5.hexdigest())}")
        print(f"[+] SHA256: {format(sha256.hexdigest())}")
    
        # Type of file
        print(f'[+] File type: {magic.from_file(file)} bytes')

        # ...
    except Exception as e:
        log_error('ERROR', f"An error occurred: {e}")

def remove(rm):
    # Delete file or directory 
    log('INFO', f'Delete {rm} ...')
    try:
        if os.path.isfile(rm):
            os.unlink(rm)
        else:
            os.rmdir(rm)
        log('INFO', f"Delete Sucess!!")
    except Exception as e:
        log_error('ERROR', f"An error occurred: {e}")

def compile_rules(sigpath, output_dir=RULES_COMPILE_DIR):
    log('INFO', 'Compiling Yara rules...')
    
    compile_rules_dict = {}
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        log('INFO', f"Created directory: {output_dir}")
    
    for dirpath, _, filenames in os.walk(sigpath):
        for file in filenames:
            yara_path = os.path.join(dirpath, file)
            rule_name = os.path.splitext(file)[0]
            try:
                compiled_rule_path = os.path.join(output_dir, f"{rule_name}.yarc")
                compiled_rule = yara.compile(yara_path)
                compiled_rule.save(compiled_rule_path)
                compile_rules_dict[rule_name] = compiled_rule_path
                log('INFO', f"Compiled rule: {rule_name}")
            except yara.SyntaxError as e:
                log_error('ERROR', f"Syntax error in rule '{file}': {e}")
            except Exception as e:
                log_error('ERROR', f"Failed to compile rule '{file}': {e}")
    
    output_file = os.path.join(output_dir, 'compiled.json')
    with open(output_file, 'w') as fw:
        json.dump(compile_rules_dict, fw, indent=4)
    log('INFO', f"Compiled rules saved to {output_file}!")
    
def scan_yara(path, compiled_path=RULES_COMPILE):
    try:
        # Ensure compiled rules exist
        if not os.path.exists(compiled_path):
            log_error('ERROR', 'No compiled rules file exists. Compile the rules first.')
            return
        
        # Load compiled rules
        with open(compiled_path, 'r') as f:
            compileRules = {k: yara.load(v) for k, v in json.load(f).items()}
        
        filePath = get_files(path)

        log('INFO', f'Scanning path {path}')
        for fileName in filePath:
            print(f'[File] {fileName:40}', end='')
            matched = False
            for rule_name, rule in compileRules.items():
                matches = rule.match(fileName)
                if matches:
                    print(f'\t{t.red}[+] {rule_name}{t.end}')
                    matched = True
                    break
            if not matched:
                print(f'\t{t.green}[+] Not malcious file{t.end}')

    except Exception as e:
        log_error('ERROR', f"An error occurred: {e}")

def update_yararule():
    pass


# ---- GENERATION NEW RULES -----
def get_pestudio_score(string):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""

def filter_string_set(string_set):
    localStringScores = {}
    stringScores = {}
    result = []

    for string in string_set:
        goodTF = False
        goodcount = 0
        if string in good_string:
            goodTF = True
            goodcount = good_string[string]

        if goodTF:
            localStringScores[string] = (goodcount * -1) + 5
        else:
            localStringScores[string] = 0

        if pestudio_available:
            (pescore, type) = get_pestudio_score(string)
            if type != "":
                if goodTF:
                    pescore = pescore - (goodcount / 1000.0)
                localStringScores[string] = pescore
        
        if not goodTF:
            # Reduction
            if ".." in string:
                localStringScores[string] -= 5
            if "   " in string:
                localStringScores[string] -= 5
            # Packer Strings
            if re.search(r'(WinRAR\\SFX)', string):
                localStringScores[string] -= 4
            # US ASCII char
            if "\x1f" in string:
                localStringScores[string] -= 4
            # Chains of 00s
            if string.count('0000000000') > 2:
                localStringScores[string] -= 5
            # Repeated characters
            if re.search(r'(?!.* ([A-Fa-f0-9])\1{8,})', string):
                localStringScores[string] -= 5

            # Certain strings add-ons ----------------------------------------------
            # Extensions - Drive
            if re.search(r'[A-Za-z]:\\', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Relevant file extensions
            if re.search(r'(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|'
                         r'\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # System keywords
            if re.search(r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Protocol Keywords
            if re.search(r'(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Connection keywords
            if re.search(r'(error|http|closed|fail|version|proxy)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Browser User Agents
            if re.search(r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Temp and Recycler
            if re.search(r'(TEMP|Temporary|Appdata|Recycler)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Malicious keywords - hacktools
            if re.search(r'(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|'
                         r'credentials|creds|coded|p0c|Content|host)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Network keywords
            if re.search(r'(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # Drive
            if re.search(r'([C-Zc-z]:\\)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # IP
            if re.search(
                    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                    string, re.IGNORECASE):  # IP Address
                localStringScores[string] += 5
            # Copyright Owner
            if re.search(r'(coded | c0d3d |cr3w\b|Coded by |codedby)', string, re.IGNORECASE):
                localStringScores[string] += 7
            # Extension generic
            if re.search(r'\.[a-zA-Z]{3}\b', string):
                localStringScores[string] += 3
            # All upper case
            if re.search(r'^[A-Z]{6,}$', string):
                localStringScores[string] += 2.5
            # All lower case
            if re.search(r'^[a-z]{6,}$', string):
                localStringScores[string] += 2
            # All lower with space
            if re.search(r'^[a-z\s]{6,}$', string):
                localStringScores[string] += 2
            # All characters
            if re.search(r'^[A-Z][a-z]{5,}$', string):
                localStringScores[string] += 2
            # URL
            if re.search(r'(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)', string):
                localStringScores[string] += 2.5
            # certificates
            if re.search(r'(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)', string, re.IGNORECASE):
                localStringScores[string] -= 4
            # Parameters
            if re.search(r'( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Directory
            if re.search(r'([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\', string):
                localStringScores[string] += 4
            # Executable - not in directory
            if re.search(r'^[^\\]+\.(exe|com|scr|bat|sys)$', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Date placeholders
            if re.search(r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Placeholders
            if re.search(r'[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]', string, re.IGNORECASE):
                localStringScores[string] += 3
            # String parts from file system elements
            if re.search(r'(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)', string,
                         re.IGNORECASE):
                localStringScores[string] += 3
            # Programming
            if re.search(r'(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # Credentials
            if re.search(r'(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|'
                         r'identif|account|login|auth|privilege)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Malware
            if re.search(r'(\.[a-z]/[^/]+\.txt|)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Variables
            if re.search(r'%[A-Z_]+%', string, re.IGNORECASE):
                localStringScores[string] += 4
            # RATs / Malware
            if re.search(r'(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Missed user profiles
            if re.search(r'[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|'
                         r'Usuários)[\\]', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Strings: Words ending with numbers
            if re.search(r'^[A-Z][a-z]+[0-9]+$', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Spying
            if re.search(r'(implant)', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Program Path - not Programs or Windows
            if re.search(r'^[Cc]:\\\\[^PW]', string):
                localStringScores[string] += 3
            # Special strings
            if re.search(r'(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Parameters
            if re.search(r'( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])', string):
                localStringScores[string] += 4
            # File
            if re.search(r'^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Comment Line / Output Log
            if re.search(r'^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )', string):
                localStringScores[string] += 4
            # Output typo / special expression
            if re.search(r'(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)', string):
                localStringScores[string] += 4
            # Base64
            if re.search(r'^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', string) and \
                    re.search(r'[A-Za-z]', string) and re.search(r'[0-9]', string):
                localStringScores[string] += 7
            # Base64 Executables
            if re.search(r'(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|'
                         r'TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)', string):
                localStringScores[string] += 5
            # Malicious intent
            if re.search(r'(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|'
                         r'traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|'
                         r'payload|inject|back conn)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Privileges
            if re.search(r'(administrator|highest|system|debug|dbg|admin|adm|root) privilege', string, re.IGNORECASE):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r'(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)', string):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r'(\.exe|\.dll|\.sys)$', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Indicators that string is valid
            if re.search(r'(^\\\\)', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Compiler output directories
            if re.search(r'(\\Release\\|\\Debug\\|\\bin|\\sbin)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Special - Malware related strings
            if re.search(r'(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)', string):
                localStringScores[string] += 4
            # Powershell
            if re.search(r'(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net.Webclient|Invoke[A-Z]|'
                         r'Net.WebClient|-w hidden |-encoded'
                         r'-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # WMI
            if re.search(r'( /c WMIC)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Windows Commands
            if re.search(r'( net user | net group |ping |whoami |bitsadmin |rundll32.exe javascript:|'
                         r'schtasks.exe /create|/c start )',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # JavaScript
            if re.search(r'(new ActiveXObject\("WScript.Shell"\).Run|.Run\("cmd.exe|.Run\("%comspec%\)|'
                         r'.Run\("c:\\Windows|.RegisterXLL\()', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Signing Certificates
            if re.search(r'( Inc | Co.|  Ltd.,| LLC| Limited)', string):
                localStringScores[string] += 2
            # Privilege escalation
            if re.search(r'(sysprep|cryptbase|secur32)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Webshells
            if re.search(r'(isset\($post\[|isset\($get\[|eval\(Request)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(r'(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)', string,
                         re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(r'([+] |[-] |[*] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|'
                         r'elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump | '
                         r'back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|'
                         r'shell commands| spawning |] target |] Transmi|] Connect|] connect|] Dump|] command |'
                         r'] token|] Token |] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|'
                         r'race condition|Token system |LoaderConfig| add user |ile upload |ile download |'
                         r'Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|'
                         r'Password: |loading dll|.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|'
                         r'sploit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)',
                         string, re.IGNORECASE):
                localStringScores[string] += 4
            # Mutex / Named Pipes
            if re.search(r'(Mutex|NamedPipe|\\Global\\|\\pipe\\)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Usage
            if re.search(r'(isset\($post\[|isset\($get\[)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Hash
            if re.search(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Persistence
            if re.search(r'(sc.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Unix/Linux
            if re.search(r'(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )', string,
                         re.IGNORECASE):
                localStringScores[string] += 3
            # Attack
            if re.search(
                    r'(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # Strings with less value
            if re.search(r'(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)', string, re.IGNORECASE):
                localStringScores[string] -= 5
            # VB Backdoors
            if re.search(
                    r'(kill|wscript|plugins|svr32|Select |)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # Suspicious strings - combo / special characters
            if re.search(
                    r'([a-z]{4,}[!\?]|\[[!+\-]\] |[a-zA-Z]{4,}...)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            if re.search(
                    r'(-->|!!!| <<< | >>> )',
                    string, re.IGNORECASE):
                localStringScores[string] += 5
            # Swear words
            if re.search(
                    r'\b(fuck|damn|shit|penis)\b',
                    string, re.IGNORECASE):
                localStringScores[string] += 5
            # Scripting Strings
            if re.search(
                    r'(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # UACME Bypass
            if re.search(
                    r'(Elevation|pwnd|pawn|elevate to)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            if re.search(r'(rundll32\.exe$|kernel\.dll$)', string, re.IGNORECASE):
                localStringScores[string] -= 4
        stringScores[string] = localStringScores[string]
        if int(stringScores[string]) >= 5:
            result.append(string)
    return result

def extract_string(file_path, min_length=4):
    strings = []
    try:
        with open(file_path, "rb") as f:
            binary_data = f.read()
            pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
            matches = re.findall(pattern, binary_data)
            strings = [match.decode('utf-8', errors='ignore') for match in matches]
    except FileNotFoundError:
        log_error('ERROR', f"Path '{file_path}' does not exist.")
    except Exception as e:
        log_error('ERROR', f"An error occurred: {e}") 
    return strings

def parse_dir(dir):
    strings = []
    try:
        log('INFO', f"Processing ... ")
        for filePath in get_files(dir):
            extension = os.path.splitext(filePath)[1].lower()
            if not extension in RELEVANT_EXTENSIONS:
                continue          
            strings = extract_string(filePath)
                
    except Exception as e:
        log_error('ERROR', f"An error occurred: {e}") 

    return strings

def gen_rules(rules): 
    log('INFO', f'Generating {args.o} rule ...')

    argr0 = args.n 
    argr1 = args.des
    argr2 = args.a
    argr3 = DATE
    argr4 = ''
    for idx, rule in enumerate(rules):
        tmp = re.sub(r'\\', r'\\\\', rule) 
        tmp = re.sub(r'(?<!\\)"', r'\"', tmp)
        argr4 += ''.join(f'         $str{idx} = {"\"" + tmp + "\""} fullword ascii')
        argr4 += '\n'
    argr5 = 'all of them'

    return FORMAT_RULES.format(argr0, argr1, argr2, argr3, argr4, argr5)

def processing(target):
    string_stats = parse_dir(target)
    rules = filter_string_set(string_stats)

    rl = gen_rules(rules)
    path = GEN_RULES + args.o
    with open(path, 'w') as fw:
        fw.write(rl)
        fw.close()
        log('INFO', 'COMPLETE')

def init_xml():
    xml_string = {}
    tree = etree.parse(os.path.join(os.path.dirname(os.path.abspath(__file__)), BLACKLIST_STRING))

    xml_string["strings"] = tree.findall(".//string")
    xml_string["av"] = tree.findall(".//av")
    xml_string["folder"] = tree.findall(".//folder")
    xml_string["os"] = tree.findall(".//os")
    xml_string["reg"] = tree.findall(".//reg")
    xml_string["guid"] = tree.findall(".//guid")
    xml_string["ssdl"] = tree.findall(".//ssdl")
    xml_string["ext"] = tree.findall(".//ext")
    xml_string["agent"] = tree.findall(".//agent")
    xml_string["oid"] = tree.findall(".//oid")
    xml_string["priv"] = tree.findall(".//priv")

    return xml_string

def print_welcome():
    print(f'{t.yellow}-------------------------------------------------------{t.end}')
    print(f'{t.yellow}                                                       {t.end}')
    print(fr'{t.yellow}     ___             _____                       ___  {t.end}')
    print(fr'{t.yellow}    /   |____   ____|  __ \    __  ______  _____/   | {t.end}')
    print(fr'{t.yellow}   / /| | ___\_/___ | |  \ \  / / / / __ `/ ___/ /| | {t.end}')
    print(fr'{t.yellow}  / __  |/ / | | \ \| |__/  |/ /_/ / /_/ / /  / ___ | {t.end}')
    print(fr'{t.yellow} /_/  |_|_/  |_|  \_|_____ / \__, /\__,_/_/  /_/  |_| {t.end}')
    print(fr'{t.yellow}                            /____/                    {t.end}')
    print(f'{t.yellow}                                                       {t.end}')
    print(f'{t.yellow}-------------------------------------------------------{t.end}')

if __name__ == '__main__':

    start = time.time()
    
    parser = argparse.ArgumentParser(prog='python3 AMDYara.py', usage='%(prog)s [options] <file or directory>', description='AMDYara - Yara Rules Scanner and Generation', epilog=' ~~~ Make Your Computer Safer ~~~')
    parser.add_argument('-p', help='Path of file(s)', metavar='path', default=None)
    parser.add_argument('-s', help='Path of yara rules', metavar='yarapath', default='./yara-rules')
    parser.add_argument('-d', help='File details', metavar='detail', default=None)
    parser.add_argument('-r', help='Delete file or directory', metavar='delete', default=None)
    parser.add_argument('--compile', action='store_true', default=False, help='Compile yara rules')

    group = parser.add_argument_group('Generate yara rules')
    group.add_argument('--gen', action='store_true', help='Automatically generate yara rules through blacklist strings', default=False)
    group.add_argument('-i', help='Path of input malware file', metavar='input', default=None)
    group.add_argument('-o', help='Path of output rule file', metavar='output', default='Yara' + DATE + '.yara')
    group.add_argument('-n', help='Name of yara-rule', metavar='name', default='Rule_' + DATE)
    group.add_argument('-a', help='Author of yara-rule', metavar='author', default= None)
    group.add_argument('-des', help='Description yara-rule', metavar='description', default='Detect Malware')
    
    args = parser.parse_args()
    # print(args)
    print_welcome()

    if args.d:
        file_details(args.d)
    elif args.r:
        remove(args.r)
    elif args.compile: 
        compile_rules(args.s)
    elif args.p:
        scan_yara(args.p)
    elif args.gen and args.i:
        
        log('INFO', f'Loading whitelist string ...')
        good_string = Counter()
        for filePath in os.listdir(WHITELIST_STRING):
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), WHITELIST_STRING + filePath)
            gg = load(path)
            good_string.update(gg)

        log('INFO', f'Loading blacklist string ...')
        pestudio_strings = init_xml()
        pestudio_available = True
        
        processing(args.i)
    print()
        
    end = time.time()
    # print("\n\nThe time of execution of above program is :", (end-start), "ms")
