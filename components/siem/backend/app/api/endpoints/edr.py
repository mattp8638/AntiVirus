"""EDR/XDR API Endpoints

Provides API interface for Sentinel EDR agent telemetry and management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import json

from app.core.database import get_db
from app.models.edr import (
    EDRAgent,
    EDREvent,
    EDRThreat,
    EDRProcess,
    EDRNetworkConnection,
    EDRFileOperation
)
from app.schemas.edr import (
    AgentRegister,
    AgentInfo,
    EDREventCreate,
    EDREventResponse,
    ThreatDetection,
    ThreatResponse,
    AgentCommand,
    ProcessInfo,
    NetworkConnectionInfo,
    FileOperationInfo
)
from app.core.security import get_current_user

router = APIRouter(prefix="/edr", tags=["EDR"])


@router.post("/agents/register", response_model=AgentInfo)
async def register_agent(
    agent: AgentRegister,
    db: Session = Depends(get_db)
):
    """Register new EDR agent"""
    
    # Check if agent already exists
    existing = db.query(EDRAgent).filter(
        EDRAgent.agent_id == agent.agent_id
    ).first()
    
    if existing:
        # Update existing agent
        existing.last_seen = datetime.utcnow()
        existing.agent_version = agent.agent_version
        existing.os_version = agent.os_version
        existing.ip_address = agent.ip_address
        db.commit()
        return existing
    
    # Create new agent
    db_agent = EDRAgent(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        os_version=agent.os_version,
        ip_address=agent.ip_address,
        agent_version=agent.agent_version,
        status="online",
        last_seen=datetime.utcnow()
    )
    
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    
    return db_agent


@router.get("/agents", response_model=List[AgentInfo])
async def list_agents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all EDR agents"""
    
    query = db.query(EDRAgent)
    
    if status:
        query = query.filter(EDRAgent.status == status)
    
    agents = query.offset(skip).limit(limit).all()
    
    # Update status based on last_seen
    for agent in agents:
        if agent.last_seen < datetime.utcnow() - timedelta(minutes=5):
            agent.status = "offline"
        else:
            agent.status = "online"
    
    db.commit()
    
    return agents


@router.get("/agents/{agent_id}", response_model=AgentInfo)
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific agent details"""
    
    agent = db.query(EDRAgent).filter(
        EDRAgent.agent_id == agent_id
    ).first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return agent


@router.post("/events", status_code=status.HTTP_201_CREATED)
async def ingest_events(
    events: List[EDREventCreate],
    db: Session = Depends(get_db)
):
    """Ingest EDR events from agents"""
    
    for event_data in events:
        event = EDREvent(
            agent_id=event_data.agent_id,
            event_type=event_data.event_type,
            timestamp=event_data.timestamp or datetime.utcnow(),
            process_id=event_data.process_id,
            process_name=event_data.process_name,
            command_line=event_data.command_line,
            parent_process_id=event_data.parent_process_id,
            user=event_data.user,
            severity=event_data.severity,
            raw_data=event_data.raw_data
        )
        db.add(event)
    
    db.commit()
    
    return {"status": "success", "events_ingested": len(events)}


@router.get("/events", response_model=List[EDREventResponse])
async def get_events(
    skip: int = 0,
    limit: int = 100,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Query EDR events"""
    
    query = db.query(EDREvent)
    
    if agent_id:
        query = query.filter(EDREvent.agent_id == agent_id)
    
    if event_type:
        query = query.filter(EDREvent.event_type == event_type)
    
    if severity:
        query = query.filter(EDREvent.severity == severity)
    
    if start_time:
        query = query.filter(EDREvent.timestamp >= start_time)
    
    if end_time:
        query = query.filter(EDREvent.timestamp <= end_time)
    
    events = query.order_by(
        EDREvent.timestamp.desc()
    ).offset(skip).limit(limit).all()
    
    return events


@router.post("/threats", response_model=ThreatResponse)
async def report_threat(
    threat: ThreatDetection,
    db: Session = Depends(get_db)
):
    """Report threat detection from agent"""
    
    db_threat = EDRThreat(
        agent_id=threat.agent_id,
        threat_type=threat.threat_type,
        threat_name=threat.threat_name,
        severity=threat.severity,
        process_id=threat.process_id,
        process_name=threat.process_name,
        file_path=threat.file_path,
        file_hash=threat.file_hash,
        mitre_tactics=threat.mitre_tactics,
        mitre_techniques=threat.mitre_techniques,
        indicators=threat.indicators,
        ml_score=threat.ml_score,
        status="detected",
        timestamp=datetime.utcnow()
    )
    
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    
    # Trigger automated response if critical
    if threat.severity == "critical":
        # Send command to isolate endpoint
        pass
    
    return db_threat


@router.get("/threats", response_model=List[ThreatResponse])
async def get_threats(
    skip: int = 0,
    limit: int = 100,
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get threat detections"""
    
    query = db.query(EDRThreat)
    
    if agent_id:
        query = query.filter(EDRThreat.agent_id == agent_id)
    
    if severity:
        query = query.filter(EDRThreat.severity == severity)
    
    if status:
        query = query.filter(EDRThreat.status == status)
    
    threats = query.order_by(
        EDRThreat.timestamp.desc()
    ).offset(skip).limit(limit).all()
    
    return threats


@router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get threat details"""
    
    threat = db.query(EDRThreat).filter(
        EDRThreat.id == threat_id
    ).first()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return threat


@router.post("/threats/{threat_id}/respond")
async def respond_to_threat(
    threat_id: int,
    action: str,  # isolate, kill_process, quarantine, allow
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Respond to threat"""
    
    threat = db.query(EDRThreat).filter(
        EDRThreat.id == threat_id
    ).first()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Send command to agent
    command = AgentCommand(
        agent_id=threat.agent_id,
        command_type=action,
        parameters={
            "threat_id": threat_id,
            "process_id": threat.process_id
        }
    )
    
    # Update threat status
    threat.status = f"responded_{action}"
    threat.responded_at = datetime.utcnow()
    threat.responded_by = current_user.username
    
    db.commit()
    
    return {"status": "success", "action": action, "threat_id": threat_id}


@router.get("/commands")
async def get_agent_commands(
    agent_id: str,
    db: Session = Depends(get_db)
):
    """Get pending commands for agent"""
    
    # Return pending commands from queue
    # This would be implemented with a command queue
    return []


@router.get("/processes")
async def get_processes(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get running processes on endpoint"""
    
    processes = db.query(EDRProcess).filter(
        EDRProcess.agent_id == agent_id,
        EDRProcess.is_running == True
    ).all()
    
    return processes


@router.get("/network-connections")
async def get_network_connections(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get network connections from endpoint"""
    
    connections = db.query(EDRNetworkConnection).filter(
        EDRNetworkConnection.agent_id == agent_id,
        EDRNetworkConnection.state == "ESTABLISHED"
    ).all()
    
    return connections


@router.get("/file-operations")
async def get_file_operations(
    agent_id: str,
    operation_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get file operations from endpoint"""
    
    query = db.query(EDRFileOperation).filter(
        EDRFileOperation.agent_id == agent_id
    )
    
    if operation_type:
        query = query.filter(EDRFileOperation.operation_type == operation_type)
    
    operations = query.order_by(
        EDRFileOperation.timestamp.desc()
    ).limit(1000).all()
    
    return operations


@router.get("/statistics")
async def get_edr_statistics(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get EDR statistics"""
    
    total_agents = db.query(EDRAgent).count()
    online_agents = db.query(EDRAgent).filter(
        EDRAgent.status == "online"
    ).count()
    
    total_threats = db.query(EDRThreat).count()
    critical_threats = db.query(EDRThreat).filter(
        EDRThreat.severity == "critical",
        EDRThreat.status == "detected"
    ).count()
    
    recent_events = db.query(EDREvent).filter(
        EDREvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    return {
        "total_agents": total_agents,
        "online_agents": online_agents,
        "offline_agents": total_agents - online_agents,
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "events_24h": recent_events
    }
