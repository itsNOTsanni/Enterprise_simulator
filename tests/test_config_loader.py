from shared.utils.config_loader import (
    load_registry,
    get_asset,
    get_employee,
    get_access_profile,
    get_cloud_resource,
)


registry = load_registry()

print("\n========== ENTERPRISE ==========")
print(registry["enterprise"]["name"])

print("\n========== NETWORK ==========")
print(registry["network"]["cidr"])

print("\n========== WEB SERVER ==========")
print(get_asset("WEB-01"))

print("\n========== DATABASE ==========")
print(get_asset("DB-01"))

print("\n========== EMPLOYEE ==========")
print(get_employee("EMP-003"))

print("\n========== ACCESS PROFILE ==========")
print(get_access_profile("it_admin"))

print("\n========== CLOUD RESOURCE ==========")
print(get_cloud_resource("IAM-01"))