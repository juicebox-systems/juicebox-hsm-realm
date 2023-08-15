#!/usr/bin/env python3

# Checks that the `Cargo.toml` dependencies lists specify identical version
# requirements across this project and the SDK repo.

import json
import subprocess
import sys


def read_dependencies(project, path):
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    metadata = json.loads(output.stdout)

    errors = False
    project_deps = {}
    for package in metadata["packages"]:
        for dep in package["dependencies"]:
            if dep["name"] in project_deps and project_deps[dep["name"]] != dep["req"]:
                errors = True
                print(
                    f"ERROR: found distinct versions for {dep['name']} in {project}: "
                    f"{project_deps[dep['name']]} vs {dep['req']}"
                )
            else:
                project_deps[dep["name"]] = dep["req"]
    print(f"Found {len(project_deps)} direct {project} dependencies")
    return (project_deps, errors)


(hsm_deps, hsm_errors) = read_dependencies("juicebox-hsm-realm", ".")
(sdk_deps, sdk_errors) = read_dependencies("juicebox-sdk", "sdk")

common_deps = hsm_deps.keys() & sdk_deps.keys()
print(f"Found {len(common_deps)} shared dependencies")
differ = False
for name in common_deps:
    if not name.startswith("juicebox_") and hsm_deps[name] != sdk_deps[name]:
        print(
            f"ERROR: found distinct versions for {name}: "
            f"{hsm_deps[name]} in juicebox-hsm-realm vs {sdk_deps[name]} in juicebox-sdk"
        )
        differ = True


if hsm_errors or sdk_errors or differ:
    print("Encountered differing version requirements")
    sys.exit(1)
else:
    print("All version requirements agree")
