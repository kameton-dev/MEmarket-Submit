import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+){0,3}$")
_PACKAGE_EXTENSIONS = {".xap", ".appx", ".appxbundle"}
MAX_PUBLISHED_VERSIONS = 4


def parse_version(value):
    if not value or not _VERSION_PATTERN.fullmatch(value.strip()):
        return None
    return tuple(int(part) for part in value.strip().split("."))


def version_is_newer(candidate, current):
    candidate_parts = parse_version(candidate)
    current_parts = parse_version(current)
    if candidate_parts is None or current_parts is None:
        return False
    width = max(len(candidate_parts), len(current_parts))
    return (candidate_parts + (0,) * (width - len(candidate_parts))) > (
        current_parts + (0,) * (width - len(current_parts))
    )


def read_package_identity(package_path):
    def local_name(tag):
        return tag.split("}")[-1]

    with zipfile.ZipFile(package_path, "r") as package:
        names = package.namelist()
        if "WMAppManifest.xml" in names:
            root = ET.fromstring(package.read("WMAppManifest.xml"))
            app_node = next(
                (node for node in root.iter() if local_name(node.tag) == "App"),
                None,
            )
            if app_node is None:
                raise ValueError("WMAppManifest.xml does not contain an App element")
            app_id = app_node.attrib.get("ProductID", "").strip("{}")
            if not app_id:
                raise ValueError("WMAppManifest.xml does not contain a ProductID")
            return {
                "app_id": app_id,
                "version": app_node.attrib.get("Version"),
            }

        appx_manifest = next(
            (
                filename
                for filename in (
                    "AppxManifest.xml",
                    "AppxMetadata/AppxBundleManifest.xml",
                )
                if filename in names
            ),
            None,
        )
        if appx_manifest:
            root = ET.fromstring(package.read(appx_manifest))
            identity = next(
                (node for node in root.iter() if local_name(node.tag) == "Identity"),
                None,
            )
            if identity is None:
                raise ValueError("AppxManifest.xml does not contain an Identity element")
            app_id = identity.attrib.get("Name", "")
            if not app_id:
                raise ValueError("AppxManifest.xml Identity does not contain a Name")
            return {
                "app_id": app_id,
                "version": identity.attrib.get("Version"),
            }

    raise ValueError("Package does not contain a supported application manifest")


def find_published_package(app_directory, app_id):
    packages = find_published_packages(app_directory, app_id)
    return packages[-1] if packages else None


def find_published_packages(app_directory, app_id):
    directory = Path(app_directory)
    if not directory.is_dir():
        return []

    packages = []
    for package_path in sorted(directory.iterdir()):
        if not package_path.is_file() or package_path.suffix.lower() not in _PACKAGE_EXTENSIONS:
            continue
        try:
            identity = read_package_identity(package_path)
        except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError):
            continue
        if identity["app_id"] == app_id:
            packages.append((package_path, identity.get("version")))

    def sort_key(package):
        package_path, version = package
        version_parts = parse_version(version)
        if version_parts is None:
            return (0, (), package_path.name)
        return (1, version_parts + (0,) * (4 - len(version_parts)), package_path.name)

    return sorted(packages, key=sort_key)


def unique_package_name(app_directory, filename, version):
    directory = Path(app_directory)
    source_name = Path(filename).name
    if not (directory / source_name).exists():
        return source_name

    path = Path(source_name)
    versioned_name = f"{path.stem}-{version}{path.suffix}"
    candidate = versioned_name
    suffix = 2
    while (directory / candidate).exists():
        candidate = f"{path.stem}-{version}-{suffix}{path.suffix}"
        suffix += 1
    return candidate


def prune_published_packages(app_directory, app_id):
    packages = find_published_packages(app_directory, app_id)
    for package_path, _ in packages[:-MAX_PUBLISHED_VERSIONS]:
        package_path.unlink()