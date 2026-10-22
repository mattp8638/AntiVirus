from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.ioc_validator.router import ValidationRequest, validate, router as ioc_router
from modules.threatgate.router import DecisionRequest, IOCInput, decide, router as threatgate_router
from modules.blocklist.router import BlockRequest, DecisionItem, build, router as blocklist_router
from modules.endpoint.router import router as endpoint_router
from modules.exposure.router import router as exposure_router
from modules.cve.router import router as cve_router
from modules.phish.router import router as phish_router
from modules.settings.router import router as settings_router
from modules.email_intel.router import router as email_intel_router
from modules.investigator.router import router as investigator_router
from modules.cases.router import router as cases_router
from modules.persistence.router import router as persistence_router
from modules.network.router import router as network_router
from modules.ioc_scanner.router import router as ioc_scanner_router
from modules.av_bridge.router import router as av_bridge_router
from modules.av_engine.router import router as av_engine_router
from modules.topology.router import router as topology_router
from modules.threat_feeds.router import router as threat_feeds_router
from modules.security_suite.router import router as security_suite_router
from modules.agent_poller import poller as agent_poller

app = FastAPI(title="Sentinel Platform", version="6.9.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ioc_router, prefix="/api/ioc", tags=["IOC Validator"])
app.include_router(threatgate_router, prefix="/api/threatgate", tags=["ThreatGate"])
app.include_router(blocklist_router, prefix="/api/blocklist", tags=["BlocklistForge"])
app.include_router(endpoint_router, prefix="/api/endpoint", tags=["EndpointRisk"])
app.include_router(exposure_router, prefix="/api/exposure", tags=["ExposureScout"])
app.include_router(cve_router, prefix="/api/cve", tags=["CVE Watchdog"])
app.include_router(phish_router, prefix="/api/phish", tags=["PhishGuard"])
app.include_router(settings_router, prefix="/api/settings", tags=["Settings"])
app.include_router(email_intel_router, prefix="/api/email-intel", tags=["Email Intelligence"])
app.include_router(investigator_router, prefix="/api/investigator", tags=["Investigator"])
app.include_router(cases_router, prefix="/api/cases", tags=["Case Management"])
app.include_router(persistence_router, prefix="/api/persistence", tags=["Persistence Scanner"])
app.include_router(network_router, prefix="/api/network", tags=["Network Connection Monitor"])
app.include_router(ioc_scanner_router, prefix="/api/ioc-scanner", tags=["IOC Scanner"])
app.include_router(av_engine_router, prefix="/api/av-native", tags=["Sentinel Native AV Engine"])
app.include_router(av_bridge_router, prefix="/api/av", tags=["Fenrir AV Bridge"])
app.include_router(topology_router, prefix="/api/topology", tags=["Network Topology"])
app.include_router(threat_feeds_router, prefix="/api/threat-feeds", tags=["Threat Feed Aggregator"])
app.include_router(security_suite_router, prefix="/api/security-suite", tags=["Canonical Security Suite"])


@app.on_event("startup")
async def _startup():
    try:
        agent_poller.start()
    except Exception:
        pass


@app.on_event("shutdown")
async def _shutdown():
    try:
        await agent_poller.stop()
    except Exception:
        pass

@app.get("/")
def root():
    return {
        "status": "Sentinel running",
        "mode": "focused defensive MVP platform",
        "modules": ["ioc", "ioc_scanner", "threat_feeds", "av_native", "av_bridge", "endpoint", "investigator", "timeline", "persistence", "process", "network", "topology", "phish", "baseline", "cve", "cases", "settings", "security_suite"],
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/api/pipeline/run")
def run_pipeline(payload: dict):
    validation = validate(ValidationRequest(input=payload.get("input", "")))
    decision_input = DecisionRequest(
        iocs=[
            IOCInput(value=item.value, type=item.type.value if hasattr(item.type, "value") else str(item.type), confidence=item.confidence)
            for item in validation.get("results", [])
        ]
    )
    decisions = decide(decision_input)
    block_request = BlockRequest(
        decisions=[DecisionItem(value=item["value"], decision=item["decision"]) for item in decisions.get("decisions", [])]
    )
    blocklist = build(block_request)
    return {"validation": validation, "decisions": decisions, "blocklist": blocklist}
