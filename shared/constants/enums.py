from enum import Enum


class SimulationMode(str, Enum):
    NORMAL = "normal"
    ATTACK = "attack"
    MIXED = "mixed"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    DENIED = "denied"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    WEB = "web"
    DATABASE = "database"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    PRIVILEGE = "privilege"
    CLOUD = "cloud"
    IAM = "iam"
    STORAGE = "storage"
    API = "api"
    SECURITY_CONFIGURATION = "security_configuration"


class Protocol(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"
    UDP = "UDP"


class AssetType(str, Enum):
    WEB_SERVER = "web_server"
    DATABASE_SERVER = "database_server"
    EMPLOYEE_WORKSTATION = "employee_workstation"
    CLOUD_ENVIRONMENT = "cloud_environment"