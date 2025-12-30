#!/usr/bin/env python3
import sys
import json
import hashlib
import argparse

# --- Constants ---
ALLOWED_INTENT = {"approve", "deny", "request"}
ALLOWED_ACT = {"access", "upsert", "execute"}
ALLOWED_KIND = {"Human", "IAD", "CLS"}
ALLOWED_OBJK = {"dataset", "model", "ledger", "capability"}
ALLOWED_SCOPE = {"read", "write", "execute"}

def parse_line(line: str) -> dict:
    """Parses a single line of HGL text into a structured dictionary."""
    
    # Normalize whitespace
    line = " ".join(line.strip().split())
    
    parts = {}
    order = ["SUBJ:", "INTENT:", "ACT:", "OBJ:", "CONSENT:", "POLICY:", "PROOF:"]
    rest = line

    # Parse tags in order
    for i, tag in enumerate(order):
        idx = rest.find(tag)
        if idx == -1:
            continue
        
        # Find the start of the next tag to determine the end of the current one
        nxt = len(rest)
        for t2 in order[i + 1:]:
            j = rest.find(t2, idx + len(tag))
            if j != -1 and j < nxt:
                nxt = j
        
        parts[tag[:-1]] = rest[idx + len(tag):nxt].strip()

    # Validate required fields
    for k in ["SUBJ", "INTENT", "ACT", "OBJ"]:
        if k not in parts:
            sys.exit(f"ParseError: missing required field {k}")

    # Parse Subject
    try:
        kind, subj_id = parts["SUBJ"].split(":", 1)
    except ValueError:
        sys.exit("ParseError: SUBJ must look like Kind:identifier")
    
    if kind not in ALLOWED_KIND:
        sys.exit("ParseError: invalid subject kind")

    # Parse Intent & Act
    intent = parts["INTENT"]
    act = parts["ACT"]
    
    if intent not in ALLOWED_INTENT:
        sys.exit("ParseError: invalid INTENT")
    if act not in ALLOWED_ACT:
        sys.exit("ParseError: invalid ACT")

    # Parse Object
    try:
        obj_kind, obj_id = parts["OBJ"].split("/", 1)
    except ValueError:
        sys.exit("ParseError: OBJ must look like kind/id")
    
    if obj_kind not in ALLOWED_OBJK:
        sys.exit("ParseError: invalid OBJ kind")

    # Construct Base Object
    out = {
        "sentence_type": "COOP_SENTENCE",
        "v": "0.1",
        "subj": {"kind": kind, "id": subj_id},
        "intent": intent,
        "act": act,
        "obj": {"kind": obj_kind, "id": obj_id}
    }

    # Optional: Consent
    if "CONSENT" in parts and parts["CONSENT"]:
        try:
            scope, until = parts["CONSENT"].split("@", 1)
        except ValueError:
            sys.exit("ParseError: CONSENT must look like scope@until")
        
        if scope not in ALLOWED_SCOPE:
            sys.exit("ParseError: invalid CONSENT scope")
        
        out["consent"] = {"scope": scope, "until": until.strip()}

    # Optional: Policy
    if "POLICY" in parts and parts["POLICY"]:
        toks = [t for t in parts["POLICY"].replace(",", " ").split() if t]
        out["policy"] = {"halt_if": toks}

    # Optional: Proof
    if "PROOF" in parts and parts["PROOF"]:
        prov = {}
        for kv in parts["PROOF"].split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                k = k.strip().lower()
                v = v.strip()
                
                if k in ("sha256", "hash"):
                    if len(v) != 64 or any(c not in "0123456789abcdefABCDEF" for c in v):
                        sys.exit("ParseError: PROOF.sha256 must be 64 hex chars")
                    prov["sha256"] = v
                elif k in ("sig", "sig_ed25519"):
                    prov["sig_ed25519"] = v
        
        if prov:
            out["provenance"] = prov

    return out

def canon_json(d: dict) -> str:
    """Returns canonical JSON string (sorted keys, no spaces)."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"))

def main():
    parser = argparse.ArgumentParser(description="Helix Glyph Language (HGL) Compiler")
    parser.add_argument("cmd", choices=["compile", "canon", "hash"], help="Command to execute")
    parser.add_argument("file", help="Input file path")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
            
        if args.cmd == "compile":
            # Parse HGL text to JSON
            parsed = parse_line(content)
            print(canon_json(parsed))
            
        elif args.cmd == "canon":
            # Canonicalize existing JSON
            data = json.loads(content)
            print(canon_json(data))
            
        elif args.cmd == "hash":
            # Calculate SHA256 of canonical JSON
            data = json.loads(content)
            canonical = canon_json(data).encode("utf-8")
            print(hashlib.sha256(canonical).hexdigest())
            
    except FileNotFoundError:
        sys.exit(f"Error: File '{args.file}' not found.")
    except json.JSONDecodeError:
        sys.exit(f"Error: Failed to decode JSON from '{args.file}'.")
    except Exception as e:
        sys.exit(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
