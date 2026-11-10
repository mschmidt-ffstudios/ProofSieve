"""Build a hash-locked runtime from the resolved reference installation."""

from hashlib import sha256
from pathlib import Path
import sys

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version


def main():
    requirements, directory = (Path(arg) for arg in sys.argv[1:])
    expected = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        requirement = Requirement(line)
        specifier, = requirement.specifier
        if specifier.operator != "==" or requirement.extras or requirement.marker:
            raise ValueError("The reference runtime must contain exact distribution versions")
        expected[canonicalize_name(requirement.name)] = Version(specifier.version)

    locked = {}
    for wheel in directory.glob("*.whl"):
        name, version, _, _ = parse_wheel_filename(wheel.name)
        if expected.get(name) != version or name in locked:
            raise ValueError(f"Unexpected runtime wheel {wheel.name}")
        digest = sha256()
        with wheel.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        locked[name] = f"{name}=={version} --hash=sha256:{digest.hexdigest()}"
    if locked.keys() != expected.keys():
        raise ValueError("The wheel set does not match the resolved reference runtime")
    print("\n".join(locked[name] for name in sorted(locked)))


if __name__ == "__main__":
    main()
