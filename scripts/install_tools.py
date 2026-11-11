"""Install checksum-pinned scanner binaries on Linux x86-64 CI runners."""

import argparse
import hashlib
import io
import json
import platform
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def download(url):
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'container-security-project'})
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=ROOT / 'tools' / 'versions.json')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        raise SystemExit('Run scanner installation in Linux x86-64, including WSL2 or GitHub Actions.')
    destination = ROOT / '.tools' / 'bin'
    destination.mkdir(parents=True, exist_ok=True)
    versions = json.loads(args.manifest.read_text(encoding='utf-8'))
    for name, specification in versions.items():
        if 'url' not in specification:
            continue
        content = download(specification['url'])
        if hashlib.sha256(content).hexdigest() != specification['sha256']:
            raise SystemExit(f'Checksum mismatch for {name}')
        if specification['archive']:
            with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
                member = next(item for item in archive.getmembers() if Path(item.name).name == name and item.isfile())
                content = archive.extractfile(member).read()
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as temporary:
            temporary.write(content)
            temporary_path = Path(temporary.name)
        temporary_path.chmod(0o755)
        shutil.move(str(temporary_path), destination / name)
        print(f'Installed {name} {specification["version"]}')


if __name__ == '__main__':
    main()
