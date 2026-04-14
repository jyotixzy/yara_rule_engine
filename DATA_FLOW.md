# YARA EML Scanner Data Flow

Ye document project ke end-to-end data flow ko explain karta hai, from `.eml` input to final malicious/clean output.

## High-Level Flow
A -> B
User command chalata hai:
yara-eml-scan --eml sample.eml
Ye command cli.py me enter hoti hai.
cli.py arguments parse karti hai:

kaunsi .eml file scan karni hai
summary chahiye ya JSON
verbose logging chahiye ya nahi
B -> C
cli.py actual scanning khud nahi karti. Ye pipeline.py ka run_pipeline() function call karti hai.
Yahi main controller hai.

C -> D
pipeline.py ek temporary workspace banata hai:

attachments yahin extract honge
archives yahin unpack honge
scan ke end me cleanup ho jayega
Example:

.tmp/yara_eml_scan_<random_id>
D -> E -> F
Ab .eml file parse hoti hai:
raw mail bytes read hote hain
Python email Message object ban jata hai
Simple words me:
raw email text -> structured email object

F -> G -> H
Ab attachments nikale jaate hain:
base64 ya quoted-printable decode hota hai
attachment ka naam decide hota hai
file disk par write hoti hai
Example:
.eml ke andar invoice.docm tha, to ab woh temp folder me ek actual file ban gaya.

H -> I -> J
Har extracted file ke liye scanner check karta hai:
ye actual me kis type ki file hai?
ZIP?
RAR?
PDF?
PE?
unknown?
Ye detect_file_type() karta hai using:

magic bytes
archive validators
J -> K
Yahan decision point aata hai:
Container type?
Matlab:

agar file archive/container hai, to andar jao
agar normal file hai, to scan queue me rakho
Example:

.docm detect hua as zip
.pdf detect hua as pdf
.rar detect hua as rar
K -> L -> I
Agar file container nikli:
usko unpack karo
andar ki child files nikalo
phir un child files par same detection dobara chalao
Isliye arrow wapas expand_containers() pe aata hai.

Ye recursive loop hai.

Example:
.docm
-> unzip
-> [Content_Types].xml
-> word/document.xml
-> word/vbaProject.bin

Ab in sab par bhi type detection aur phir scan hoga.

K -> M
Agar file container nahi hai, to usko final scan list me daal diya jata hai.
Matlab:
ab ye woh actual file hai jisko YARA scan karega.

M -> N -> O -> P
Ab rules load hote hain:
rule_loader.py third-party folders me jaata hai
.yar aur .yara files discover karta hai
compiled rule cache check karta hai
Yahan do possibilities hain:

cache hit: compiled rule direct load ho jayega
cache miss: rule compile hoga, phir cache me save hoga
Isliye repeated runs fast ho sakte hain.

P -> Q -> R
Ab actual scanning phase:
final file list lo
har file par saare compiled YARA rules run karo
scan_files() overall loop hai
scan_file() per-file scan hai

R -> S
YARA raw matches ko normalize kiya jata hai:
rule name
namespace/source
tags
metadata
Taaki output readable ho.

S -> T
Ab structured result objects bante hain:
FileScanResult
PipelineReport
Matlab ab scanner ke paas clean structured answer hai:

kaunsi files malicious
kaunsi clean
kis rule se match hua
kaunse rules compile fail hue
T -> U -> V
Finally cli.py output print karti hai:
simple summary
ya
JSON report
## File-by-File Role

### 1. `cli.py`

Kaam:
- command-line arguments lena
- logging mode decide karna
- pipeline call karna
- final result ko summary ya JSON me print karna

Important functions:
- `build_parser()` : CLI options define karta hai
- `format_summary()` : malicious/clean output banata hai
- `main()` : full CLI entrypoint hai

### 2. `pipeline.py`

Kaam:
- full workflow orchestrate karna
- temp workspace banana
- parser, unpacker, rule loader, scanner ko sahi sequence me call karna
- cleanup handle karna

Important function:
- `run_pipeline()` : poora end-to-end scan isi function se chalta hai

### 3. `eml_parser.py`

Kaam:
- raw `.eml` file parse karna
- attachments decode karna
- attachment bytes ko disk par likhna
- initial `ExtractedFile` objects banana

Important functions:
- `parse_eml()` : `.eml` ko email message object me convert karta hai
- `safe_attachment_name()` : attachment filename normalize karta hai
- `extract_attachments()` : decoded attachments save karta hai

### 4. `file_types.py`

Kaam:
- extension par trust na karke actual file type detect karna
- magic bytes aur archive validators use karna

Important function:
- `detect_file_type()` : file ka real type batata hai

Example:
- `.docm` internally ZIP nikle to `zip` return hoga
- `.exe` me `MZ` header ho to `pe` return hoga

### 5. `container_unpacker.py`

Kaam:
- archive/container files ko recursively unpack karna
- nested files ko queue me daalna
- path traversal aur oversized file jaise risks handle karna

Important functions:
- `is_container_type()` : type container hai ya nahi
- `unpack_zip()` / `unpack_tar()` / `unpack_gzip()` etc.
- `unpack_container()` : correct unpacker choose karta hai
- `expand_containers()` : recursive expansion ka main loop

### 6. `rule_loader.py`

Kaam:
- third-party repos se YARA rules discover karna
- compiled rule cache use karna
- broken rule files isolate karna

Important functions:
- `iter_rule_files()` : `.yar/.yara` files ki list banata hai
- `compile_rule_files()` : rules compile/load karta hai
- `_load_cached_rules()` : cache se compiled rule load karta hai
- `_save_cached_rules()` : newly compiled rule cache me save karta hai

### 7. `scanner.py`

Kaam:
- har final file par YARA matching chalana
- matches ko normalize karna
- malicious vs clean result banana

Important functions:
- `_normalize_match()` : raw match ko `RuleMatch` model me convert karta hai
- `scan_file()` : ek file par saare rules chalata hai
- `scan_files()` : final file list par scan run karta hai

### 8. `models.py`

Kaam:
- shared structured objects define karna

Main models:
- `ExtractedFile`
- `RuleLoadError`
- `RuleMatch`
- `FileScanResult`
- `PipelineReport`

Ye models parsing, unpacking, scanning, aur reporting ke beech data pass karte hain.

### 9. `config.py`

Kaam:
- global paths aur limits rakhna

Examples:
- `THIRD_PARTY_ROOT`
- `RUNTIME_TEMP_ROOT`
- `CACHE_ROOT`
- `RULE_SOURCE_PATHS`
- `MAX_RECURSION_DEPTH`

### 10. `logging_utils.py`

Kaam:
- normal aur verbose logging ka level set karna

## Detailed Runtime Sequence

1. User `yara-eml-scan --eml file.eml` run karta hai.
2. `cli.py` arguments parse karta hai.
3. `pipeline.py` temp workspace banati hai.
4. `eml_parser.py` `.eml` parse karke attachments decode karti hai.
5. Har attachment disk par save hota hai.
6. `container_unpacker.py` har extracted file ka real type detect karti hai.
7. Agar file container nikle to usko unpack kiya jata hai.
8. Ye process recursively repeat hota hai jab tak final real files na mil jayein.
9. `rule_loader.py` third-party folders se YARA rules load karti hai.
10. Cache available ho to compiled rules `.cache/compiled_rules` se load hote hain.
11. `scanner.py` har final file par YARA match chalati hai.
12. Har hit ko `RuleMatch` me convert kiya jata hai.
13. File-level result `FileScanResult` me store hota hai.
14. Sab results ko `PipelineReport` me pack kiya jata hai.
15. `cli.py` final summary ya JSON print kar deti hai.

## Data Objects Flow

```mermaid
flowchart LR
    A[".eml path (string)"] --> B["parse_eml()"]
    B --> C["Message object"]
    C --> D["extract_attachments()"]
    D --> E["list[ExtractedFile]"]
    E --> F["expand_containers()"]
    F --> G["expanded list[ExtractedFile]"]
    G --> H["scan_files()"]
    H --> I["list[FileScanResult]"]
    I --> J["PipelineReport"]
    J --> K["Summary output / JSON output"]
```

## Temp and Cache Folders

### Temp workspace

Path:
- `.tmp/yara_eml_scan_<id>`

Use:
- extracted attachments
- unpacked nested archive files
- temporary scan workspace

### Rule cache

Path:
- `.cache/compiled_rules`

Use:
- compiled YARA rule binaries
- metadata for cache validation

## Why This Design Is Useful

- File extension spoofing se bachata hai
- Nested archive ke andar actual payload tak pahunchta hai
- Broken third-party rules poore scan ko crash nahi karte
- Rule cache repeated scans ko faster banata hai
- Structured models reporting ko clean aur maintainable banate hain

Note : 
---jo cache use ho raha hai wo simple file-based local cache hai
---ye code bina internet ke chal jayega.