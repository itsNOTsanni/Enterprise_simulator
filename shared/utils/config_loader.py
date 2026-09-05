from pathlib import Path
from typing import Any, Dict

import yaml


# Project root:
# Enterprise_simulator/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

REGISTRY_PATH = PROJECT_ROOT / "config" / "asset_registry.yaml"

# Cached parsed registry. Loaded from disk once, then reused for the
# rest of the process -- the registry doesn't change while a simulator
# or test suite is running, so there's no need to re-check the file on
# every call. Call reload_registry() to force a fresh read (e.g. if
# you edit asset_registry.yaml during a long-running interactive
# session and want the changes picked up without restarting).
_registry_cache: Dict[str, Any] = None


def load_registry() -> Dict[str, Any]:
    """Load the enterprise asset registry from YAML (cached after first call)."""

    global _registry_cache

    if _registry_cache is not None:
        return _registry_cache

    if not REGISTRY_PATH.exists():
        raise FileNotFoundError(
            f"Asset registry not found: {REGISTRY_PATH}"
        )

    with open(REGISTRY_PATH, "r", encoding="utf-8") as file:
        registry = yaml.safe_load(file)

    if registry is None:
        raise ValueError("Asset registry is empty.")

    _registry_cache = registry

    return registry


def reload_registry() -> Dict[str, Any]:
    """Force a fresh read of asset_registry.yaml, bypassing the cache."""

    global _registry_cache
    _registry_cache = None
    return load_registry()


def get_asset(asset_id: str) -> Dict[str, Any]:
    """Return an asset by its asset_id."""

    registry = load_registry()

    for asset in registry.get("assets", []):
        if asset.get("asset_id") == asset_id:
            return asset

    raise ValueError(f"Asset not found: {asset_id}")


def get_employee(employee_id: str) -> Dict[str, Any]:
    """Return an employee by employee_id."""

    registry = load_registry()

    for employee in registry.get("employees", []):
        if employee.get("employee_id") == employee_id:
            return employee

    raise ValueError(f"Employee not found: {employee_id}")


def get_access_profile(profile_name: str) -> Dict[str, Any]:
    """Return an access profile."""

    registry = load_registry()

    profile = registry.get(
        "access_profiles", {}
    ).get(profile_name)

    if profile is None:
        raise ValueError(
            f"Access profile not found: {profile_name}"
        )

    return profile


def get_cloud_resource(resource_id: str) -> Dict[str, Any]:
    """Return a cloud resource by resource_id."""

    registry = load_registry()

    for resource in registry.get("cloud_resources", []):
        if resource.get("resource_id") == resource_id:
            return resource

    raise ValueError(
        f"Cloud resource not found: {resource_id}"
    )