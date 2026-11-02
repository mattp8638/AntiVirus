import uuid
from sqlalchemy import Column, String, Text, Boolean, TIMESTAMP, ForeignKey, JSON, Integer
from sqlalchemy.sql import func
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class ConfigurationProfile(Base):
    __tablename__ = "configuration_profiles"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    profile_type = Column(String)
    description = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class ConfigurationItem(Base):
    __tablename__ = "configuration_items"
    id = Column(String, primary_key=True, default=gen_uuid)
    profile_id = Column(String, ForeignKey("configuration_profiles.id"), nullable=False)
    config_key = Column(String, nullable=False)
    desired_value = Column(Text)
    enforcement_mode = Column(String)

class AssetConfigurationProfile(Base):
    __tablename__ = "asset_configuration_profiles"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, nullable=False)
    profile_id = Column(String, ForeignKey("configuration_profiles.id"), nullable=False)
    assigned_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class PatchCatalog(Base):
    __tablename__ = "patch_catalog"
    id = Column(String, primary_key=True, default=gen_uuid)
    vendor = Column(String)
    product = Column(String)
    patch_id = Column(String)
    release_date = Column(TIMESTAMP(timezone=True))
    severity = Column(Integer)

class AssetPatch(Base):
    __tablename__ = "asset_patches"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, nullable=False)
    patch_id = Column(String, ForeignKey("patch_catalog.id"), nullable=False)
    status = Column(String)
    detected_at = Column(TIMESTAMP(timezone=True))
    installed_at = Column(TIMESTAMP(timezone=True))

class PatchJob(Base):
    __tablename__ = "patch_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    psa_case_id = Column(String)
    scheduled_for = Column(TIMESTAMP(timezone=True))
    reboot_policy = Column(String)
    status = Column(String)

class Script(Base):
    __tablename__ = "scripts"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String)
    language = Column(String)
    content = Column(Text)
    requires_approval = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class ScriptJob(Base):
    __tablename__ = "script_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    script_id = Column(String, ForeignKey("scripts.id"))
    asset_id = Column(String)
    psa_task_id = Column(String)
    status = Column(String)
    started_at = Column(TIMESTAMP(timezone=True))
    completed_at = Column(TIMESTAMP(timezone=True))

class ScriptResult(Base):
    __tablename__ = "script_results"
    id = Column(String, primary_key=True, default=gen_uuid)
    job_id = Column(String, ForeignKey("script_jobs.id"))
    stdout = Column(Text)
    stderr = Column(Text)
    exit_code = Column(Integer)
    hash = Column(String)

class SoftwarePackage(Base):
    __tablename__ = "software_packages"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String)
    version = Column(String)
    installer_uri = Column(String)
    hash = Column(String)

class DeploymentJob(Base):
    __tablename__ = "deployment_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    package_id = Column(String, ForeignKey("software_packages.id"))
    asset_id = Column(String)
    psa_case_id = Column(String)
    status = Column(String)
    executed_at = Column(TIMESTAMP(timezone=True))

class RemoteSession(Base):
    __tablename__ = "remote_sessions"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String)
    initiated_by = Column(String)
    session_type = Column(String)
    started_at = Column(TIMESTAMP(timezone=True))
    ended_at = Column(TIMESTAMP(timezone=True))
    recorded = Column(Boolean, default=False)

class RMMEvidence(Base):
    __tablename__ = "rmm_evidence"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String)
    evidence_type = Column(String)
    related_entity = Column(String)
    related_id = Column(String)
    storage_uri = Column(String)
    hash = Column(String)
    captured_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class DeviceInventory(Base):
    __tablename__ = "device_inventory"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String)
    hostname = Column(String)
    os_name = Column(String)
    os_version = Column(String)
    serial_number = Column(String)
    collected_at = Column(TIMESTAMP(timezone=True))
