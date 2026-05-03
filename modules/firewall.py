"""Firewall (UFW) scanner & actions"""
from modules.helpers import run


def scan_firewall():
    """Parse ufw status + numbered rules"""
    result = {"status": "inactive", "rules": [], "error": None}
    try:
        out, _, _ = run(["sudo", "-n", "ufw", "status", "numbered"])
        if "Status: active" in out:
            result["status"] = "active"
        elif "Status: inactive" in out:
            return result

        actions = ["ALLOW IN", "DENY IN", "ALLOW OUT", "DENY OUT", "LIMIT IN", "REJECT IN"]
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("["):
                continue
            # Find action keyword
            act_idx = -1
            for a in actions:
                idx = line.upper().find(a)
                if idx != -1:
                    act_idx = idx
                    break
            if act_idx == -1:
                continue
            # Extract rule number
            bracket_end = line.find("]")
            if bracket_end == -1:
                continue
            num = line[1:bracket_end].strip()
            # Port is between ] and action
            port_spec = line[bracket_end+1:act_idx].strip()
            # Rest after action
            rest = line[act_idx:].split(None, 2)
            action = rest[0].lower() + " " + rest[1].lower() if len(rest) >= 2 else rest[0].lower()
            comment = rest[2] if len(rest) >= 3 else ""
            result["rules"].append({
                "num": num, "port": port_spec,
                "action": action, "comment": comment
            })
    except Exception as e:
        result["error"] = str(e)
    return result


def fw_allow(port):
    out, err, code = run(["sudo", "-n", "ufw", "allow", str(port)])
    return {"status": "ok" if code == 0 else "error", "output": (out + err).strip()}


def fw_deny(port):
    out, err, code = run(["sudo", "-n", "ufw", "deny", str(port)])
    return {"status": "ok" if code == 0 else "error", "output": (out + err).strip()}


def fw_delete(num):
    out, err, code = run(["sudo", "-n", "ufw", "--force", "delete", str(num)])
    return {"status": "ok" if code == 0 else "error", "output": (out + err).strip()}
