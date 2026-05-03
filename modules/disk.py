"""Disk analyzer — mount points & folder size scanner with drill-down"""
import os

from modules.helpers import run


def scan_df():
    """Get df -h output for all mounts (forced English locale)"""
    try:
        out, _, _ = run(["df", "-h", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs"],
                        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        mounts = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0] == "Filesystem":
                continue
            mounts.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "avail": parts[3],
                "use_pct": parts[4],
                "mounted_on": parts[5]
            })
        mounts.sort(key=lambda m: -int(m["use_pct"].rstrip("%")) if m["use_pct"].rstrip("%").isdigit() else 0)
        return mounts
    except Exception:
        return []


def scan_path(path):
    """Scan a directory's immediate children with du, sorted by size desc"""
    path = os.path.abspath(os.path.expanduser(path.rstrip("/"))) or "/"
    if not os.path.isdir(path):
        return {"path": path, "error": "Path not found", "folders": []}

    try:
        # Get total — use df for the mount point, not du (du is slow for big dirs)
        total = "-"

        # Scan children with max-depth=1
        # Exclude virtual filesystems for root
        exclude_args = []
        if path == "/":
            exclude_args = ["--exclude=/proc", "--exclude=/sys", "--exclude=/dev", "--exclude=/run"]

        cmd = ["du", "-h", "--max-depth=1"] + exclude_args + [path]
        out, _, _ = run(cmd, timeout=30)

        folders = []
        seen = set()
        for line in out.splitlines():
            line = line.strip()
            if not line or "\t" not in line:
                continue
            size_str, fpath = line.split("\t", 1)
            # Skip the summary line (path itself)
            if fpath.rstrip("/") == path.rstrip("/"):
                total = size_str
                continue
            if fpath in seen:
                continue
            seen.add(fpath)

            try:
                if size_str.endswith("G"):
                    size_mb = float(size_str[:-1]) * 1024
                elif size_str.endswith("T"):
                    size_mb = float(size_str[:-1]) * 1024 * 1024
                elif size_str.endswith("M"):
                    size_mb = float(size_str[:-1])
                elif size_str.endswith("K"):
                    size_mb = float(size_str[:-1]) / 1024
                elif size_str.endswith("B"):
                    size_mb = float(size_str[:-1]) / 1024 / 1024
                else:
                    continue
            except ValueError:
                continue

            fname = os.path.basename(fpath)
            folders.append({
                "path": fpath,
                "name": fname,
                "size": size_str,
                "size_mb": round(size_mb, 1)
            })

        folders.sort(key=lambda f: -f["size_mb"])

        return {
            "path": path,
            "total": total,
            "folders": folders[:30],  # top 30
        }
    except Exception as e:
        return {"path": path, "error": str(e), "folders": []}
