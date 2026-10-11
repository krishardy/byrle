"""How often each Tier 1 control refuses a package nobody reported as malicious.

Builds a lockfile for each dependency set, with npm and uv resolving against the public
registries, then runs `byrle policy diff` from a policy that allows everything to one
with a single control turned on. Every version that moves is a refusal of a package in
wide use, which is what a false positive is here. Cooldown results change daily: they
count the versions published in the last seven days.

Usage: tier1_false_positives.py <byrle binary> <work dir>
"""
import os
import re
import subprocess
import sys

NPM_SETS = ["express eslint", "next react react-dom", "vite typescript vitest"]
PYPI_SETS = ["requests flask django", "numpy pandas scikit-learn matplotlib"]

ALLOW = """version: 1
cooldown_days: 0
install_scripts: allow
provenance: allow
kev: allow
yanked: allow
max_cvss: 10.0
"""
CONTROLS = {
    "cooldown_days: 7": ("cooldown_days: 0", "cooldown_days: 7"),
    "install_scripts: block": ("install_scripts: allow", "install_scripts: block"),
    "provenance: block": ("provenance: allow", "provenance: block"),
}


def lockfile(work, ecosystem, packages):
    directory = os.path.join(work, f"{ecosystem}-{packages.replace(' ', '-')}")
    os.makedirs(directory, exist_ok=True)
    if ecosystem == "npm":
        with open(os.path.join(directory, "package.json"), "w") as f:
            f.write('{"name":"m","version":"1.0.0","private":true}\n')
        subprocess.run(
            ["npm", "install", *packages.split(), "--package-lock-only", "--no-audit",
             "--no-fund", "--loglevel=error"],
            cwd=directory, check=True, capture_output=True)
        return os.path.join(directory, "package-lock.json")
    subprocess.run(["uv", "init", "-q", "--no-workspace", "--name", "m", "--python", "3.12"],
                   cwd=directory, capture_output=True)
    subprocess.run(["uv", "add", "-q", *packages.split()], cwd=directory, check=True,
                   capture_output=True)
    return os.path.join(directory, "uv.lock")


def diff(byrle, work, control, lock):
    before, after = CONTROLS[control]
    allow = os.path.join(work, "allow.yaml")
    with open(allow, "w") as f:
        f.write(ALLOW)
    turned_on = os.path.join(work, "control.yaml")
    with open(turned_on, "w") as f:
        f.write(ALLOW.replace(before, after))
    run = subprocess.run([byrle, "policy", "diff", allow, turned_on, "--lockfile", lock],
                         capture_output=True, text=True)
    out = run.stdout + run.stderr
    evaluated = int(re.search(r"(\d+) packages evaluated", out).group(1))
    unread = re.search(r"(\d+) could not be read", out)
    moved = re.findall(r"^(pkg:\S+)\s+allow -> \w+", out, re.M)
    notes = re.findall(r"^byrle policy diff: (pkg:.*)$", out, re.M)
    return evaluated, int(unread.group(1)) if unread else 0, moved, notes


def main():
    byrle, work = sys.argv[1], sys.argv[2]
    os.makedirs(work, exist_ok=True)
    locks = [(f"npm: {s}", lockfile(work, "npm", s)) for s in NPM_SETS]
    locks += [(f"pypi: {s}", lockfile(work, "pypi", s)) for s in PYPI_SETS]
    print("| Set | Control | Evaluated | Refused | Could not be read |")
    print("|---|---|---|---|---|")
    for name, lock in locks:
        for control in CONTROLS:
            evaluated, unread, moved, notes = diff(byrle, work, control, lock)
            print(f"| {name} | `{control}` | {evaluated} | {len(moved)} | {unread} |")
            for purl in moved:
                print(f"|  | | | {purl} | |")
            for note in notes:
                print(f"|  | | | | {note} |")


if __name__ == "__main__":
    main()
