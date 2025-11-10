"""
Threat Mitigation Module

This module provides comprehensive threat mitigation capabilities including:
- Vulnerability remediation workflows
- Malware removal and cleanup
- Configuration hardening
- Patch deployment automation
- Attack path disruption
- Damage assessment and containment
- Threat neutralization strategies
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import sqlite3
from collections import defaultdict
from enum import Enum
import hashlib
import subprocess
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MitigationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIALLY_COMPLETED = "partially_completed"
    VERIFICATION_REQUIRED = "verification_required"

class MitigationType(Enum):
    PATCH_DEPLOYMENT = "patch_deployment"
    MALWARE_REMOVAL = "malware_removal"
    CONFIG_HARDENING = "config_hardening"
    CREDENTIAL_ROTATION = "credential_rotation"
    VULNERABILITY_FIX = "vulnerability_fix"
    ATTACK_PATH_DISRUPTION = "attack_path_disruption"
    DATA_SANITIZATION = "data_sanitization"
    SYSTEM_REBUILD = "system_rebuild"

class RemediationPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Vulnerability:
    """Vulnerability information"""
    vuln_id: str
    cve_id: Optional[str]
    title: str
    description: str
    severity: str
    cvss_score: float
    affected_assets: List[str]
    affected_software: str
    affected_versions: List[str]
    exploit_available: bool
    patch_available: bool
    patch_details: Optional[Dict[str, Any]]
    workaround: Optional[str]
    discovered_at: datetime
    mitigated_at: Optional[datetime]

@dataclass
class MitigationAction:
    """Individual mitigation action"""
    action_id: str
    incident_id: Optional[str]
    mitigation_type: MitigationType
    priority: RemediationPriority
    status: MitigationStatus
    target_assets: List[str]
    description: str
    remediation_steps: List[Dict[str, Any]]
    estimated_duration: int  # minutes
    actual_duration: Optional[int]
    success_criteria: List[str]
    verification_steps: List[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    executed_by: str
    results: Dict[str, Any]
    rollback_plan: Optional[str]

@dataclass
class PatchDeployment:
    """Patch deployment task"""
    deployment_id: str
    patch_name: str
    patch_version: str
    kb_number: Optional[str]
    cve_ids: List[str]
    target_systems: List[str]
    deployment_method: str  # wsus, sccm, manual, script
    deployment_schedule: datetime
    maintenance_window: Dict[str, str]
    requires_reboot: bool
    test_results: Optional[Dict[str, Any]]
    deployment_status: str
    success_count: int
    failure_count: int
    created_at: datetime

@dataclass
class MalwareRemediation:
    """Malware removal task"""
    remediation_id: str
    malware_name: str
    malware_family: str
    malware_hash: str
    affected_systems: List[str]
    removal_method: str  # antivirus, manual, reimaging
    removal_steps: List[str]
    persistence_mechanisms: List[str]
    cleanup_required: bool
    verification_scans: List[str]
    status: str
    created_at: datetime
    completed_at: Optional[datetime]

@dataclass
class HardeningRule:
    """System hardening rule"""
    rule_id: str
    name: str
    description: str
    category: str  # os, network, application, database
    platform: str  # windows, linux, cisco, etc.
    severity: str
    cis_benchmark: Optional[str]
    configuration_check: str
    remediation_script: Optional[str]
    manual_steps: Optional[str]
    impact_assessment: str
    requires_testing: bool

@dataclass
class DamageAssessment:
    """Incident damage assessment"""
    assessment_id: str
    incident_id: str
    affected_systems: List[str]
    compromised_accounts: List[str]
    data_accessed: List[str]
    data_exfiltrated: bool
    estimated_data_loss: str
    system_modifications: List[Dict[str, Any]]
    persistence_found: bool
    lateral_movement: bool
    estimated_dwell_time: str
    business_impact: str
    financial_impact: Optional[float]
    assessed_at: datetime
    assessed_by: str

class ThreatMitigationEngine:
    """
    Threat Mitigation Engine
    
    Provides comprehensive threat mitigation including:
    - Vulnerability remediation
    - Malware removal and cleanup
    - System hardening
    - Patch management
    - Attack path disruption
    - Damage assessment
    """
    
    def __init__(self, data_dir: str = "../../../", config_path: str = None):
        self.data_dir = Path(data_dir)
        self.config_path = config_path
        
        # Initialize local storage
        self.db_path = self.data_dir / "threat_mitigation.db"
        self._init_local_db()
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize mitigation components
        self.vulnerabilities = {}
        self.mitigation_actions = {}
        self.patch_deployments = {}
        self.malware_remediations = {}
        self.hardening_rules = {}
        self.damage_assessments = {}
        
        # Load existing data
        self._load_mitigation_data()
        
        # Load hardening rules
        self._load_hardening_rules()
        
        logger.info("Threat Mitigation Engine initialized")
    
    def _init_local_db(self):
        """Initialize local SQLite database for mitigation data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id TEXT UNIQUE NOT NULL,
                cve_id TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_assets_json TEXT,
                affected_software TEXT,
                affected_versions_json TEXT,
                exploit_available BOOLEAN,
                patch_available BOOLEAN,
                patch_details_json TEXT,
                workaround TEXT,
                discovered_at TEXT,
                mitigated_at TEXT
            )
        ''')
        
        # Mitigation actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mitigation_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT UNIQUE NOT NULL,
                incident_id TEXT,
                mitigation_type TEXT,
                priority TEXT,
                status TEXT,
                target_assets_json TEXT,
                description TEXT,
                remediation_steps_json TEXT,
                estimated_duration INTEGER,
                actual_duration INTEGER,
                success_criteria_json TEXT,
                verification_steps_json TEXT,
                created_at TEXT,
                started_at TEXT,
                completed_at TEXT,
                executed_by TEXT,
                results_json TEXT,
                rollback_plan TEXT
            )
        ''')
        
        # Patch deployments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patch_deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_id TEXT UNIQUE NOT NULL,
                patch_name TEXT,
                patch_version TEXT,
                kb_number TEXT,
                cve_ids_json TEXT,
                target_systems_json TEXT,
                deployment_method TEXT,
                deployment_schedule TEXT,
                maintenance_window_json TEXT,
                requires_reboot BOOLEAN,
                test_results_json TEXT,
                deployment_status TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                created_at TEXT
            )
        ''')
        
        # Malware remediations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_remediations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remediation_id TEXT UNIQUE NOT NULL,
                malware_name TEXT,
                malware_family TEXT,
                malware_hash TEXT,
                affected_systems_json TEXT,
                removal_method TEXT,
                removal_steps_json TEXT,
                persistence_mechanisms_json TEXT,
                cleanup_required BOOLEAN,
                verification_scans_json TEXT,
                status TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        ''')
        
        # Hardening rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardening_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                name TEXT,
                description TEXT,
                category TEXT,
                platform TEXT,
                severity TEXT,
                cis_benchmark TEXT,
                configuration_check TEXT,
                remediation_script TEXT,
                manual_steps TEXT,
                impact_assessment TEXT,
                requires_testing BOOLEAN
            )
        ''')
        
        # Damage assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS damage_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT UNIQUE NOT NULL,
                incident_id TEXT,
                affected_systems_json TEXT,
                compromised_accounts_json TEXT,
                data_accessed_json TEXT,
                data_exfiltrated BOOLEAN,
                estimated_data_loss TEXT,
                system_modifications_json TEXT,
                persistence_found BOOLEAN,
                lateral_movement BOOLEAN,
                estimated_dwell_time TEXT,
                business_impact TEXT,
                financial_impact REAL,
                assessed_at TEXT,
                assessed_by TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load mitigation configuration"""
        default_config = {
            'patch_management': {
                'auto_deploy_critical': False,
                'require_testing': True,
                'maintenance_windows': {
                    'weekday': '02:00-04:00',
                    'weekend': '01:00-06:00'
                },
                'patch_sources': ['wsus', 'vendor_sites'],
                'rollback_enabled': True
            },
            'malware_removal': {
                'auto_remediate': False,
                'antivirus_vendor': 'generic',
                'deep_scan_enabled': True,
                'quarantine_samples': True,
                'submit_to_sandbox': True
            },
            'hardening': {
                'auto_harden': False,
                'compliance_frameworks': ['cis', 'nist', 'pci-dss'],
                'baseline_profiles': ['server', 'workstation', 'network'],
                'verify_before_apply': True
            },
            'remediation_policies': {
                'max_concurrent_actions': 10,
                'require_approval_for': ['system_rebuild', 'data_sanitization'],
                'auto_rollback_on_failure': True,
                'verification_required': True
            },
            'damage_assessment': {
                'auto_assess': True,
                'include_financial_impact': True,
                'forensics_collection': True,
                'timeline_reconstruction': True
            }
        }
        
        return default_config
    
    def _load_mitigation_data(self):
        """Load existing mitigation data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load vulnerabilities
            cursor.execute("SELECT * FROM vulnerabilities")
            for row in cursor.fetchall():
                vuln = Vulnerability(
                    vuln_id=row[1],
                    cve_id=row[2],
                    title=row[3],
                    description=row[4],
                    severity=row[5],
                    cvss_score=row[6],
                    affected_assets=json.loads(row[7] or '[]'),
                    affected_software=row[8],
                    affected_versions=json.loads(row[9] or '[]'),
                    exploit_available=bool(row[10]),
                    patch_available=bool(row[11]),
                    patch_details=json.loads(row[12]) if row[12] else None,
                    workaround=row[13],
                    discovered_at=datetime.fromisoformat(row[14]),
                    mitigated_at=datetime.fromisoformat(row[15]) if row[15] else None
                )
                self.vulnerabilities[row[1]] = vuln
            
            # Load mitigation actions
            cursor.execute("SELECT * FROM mitigation_actions")
            for row in cursor.fetchall():
                action = MitigationAction(
                    action_id=row[1],
                    incident_id=row[2],
                    mitigation_type=MitigationType(row[3]),
                    priority=RemediationPriority(row[4]),
                    status=MitigationStatus(row[5]),
                    target_assets=json.loads(row[6] or '[]'),
                    description=row[7],
                    remediation_steps=json.loads(row[8] or '[]'),
                    estimated_duration=row[9],
                    actual_duration=row[10],
                    success_criteria=json.loads(row[11] or '[]'),
                    verification_steps=json.loads(row[12] or '[]'),
                    created_at=datetime.fromisoformat(row[13]),
                    started_at=datetime.fromisoformat(row[14]) if row[14] else None,
                    completed_at=datetime.fromisoformat(row[15]) if row[15] else None,
                    executed_by=row[16],
                    results=json.loads(row[17] or '{}'),
                    rollback_plan=row[18]
                )
                self.mitigation_actions[row[1]] = action
            
            conn.close()
            logger.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities and {len(self.mitigation_actions)} mitigation actions")
            
        except Exception as e:
            logger.error(f"Error loading mitigation data: {e}")
    
    def create_vulnerability_remediation(self, vuln_id: str, target_assets: List[str] = None,
                                        incident_id: str = None) -> str:
        """
        Create vulnerability remediation action
        
        Args:
            vuln_id: Vulnerability to remediate
            target_assets: Specific assets to remediate, or None for all affected
            incident_id: Associated incident ID
            
        Returns:
            Action ID
        """
        if vuln_id not in self.vulnerabilities:
            logger.error(f"Vulnerability {vuln_id} not found")
            return None
        
        vuln = self.vulnerabilities[vuln_id]
        action_id = f"MIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Use all affected assets if not specified
        if not target_assets:
            target_assets = vuln.affected_assets
        
        # Determine remediation steps based on vulnerability
        remediation_steps = self._generate_remediation_steps(vuln)
        
        # Calculate priority
        priority = self._calculate_remediation_priority(vuln)
        
        # Create mitigation action
        action = MitigationAction(
            action_id=action_id,
            incident_id=incident_id,
            mitigation_type=MitigationType.VULNERABILITY_FIX,
            priority=priority,
            status=MitigationStatus.PENDING,
            target_assets=target_assets,
            description=f"Remediate {vuln.title} ({vuln.cve_id})",
            remediation_steps=remediation_steps,
            estimated_duration=self._estimate_remediation_duration(vuln, len(target_assets)),
            actual_duration=None,
            success_criteria=[
                f"Vulnerability {vuln.cve_id} no longer detected",
                "All target systems patched or mitigated",
                "Verification scan shows no vulnerability"
            ],
            verification_steps=[
                "Run vulnerability scanner",
                "Check patch deployment status",
                "Verify system configuration"
            ],
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            executed_by='system',
            results={},
            rollback_plan=None
        )
        
        self.mitigation_actions[action_id] = action
        self._cache_mitigation_action(action)
        
        # If patch available, create patch deployment
        if vuln.patch_available and vuln.patch_details:
            self._create_patch_deployment_from_vuln(vuln, target_assets)
        
        logger.info(f"Created vulnerability remediation action: {action_id}")
        return action_id
    
    def deploy_patch(self, patch_name: str, patch_version: str, target_systems: List[str],
                    cve_ids: List[str] = None, kb_number: str = None,
                    schedule: datetime = None) -> str:
        """
        Deploy patch to target systems
        
        Args:
            patch_name: Name of patch
            patch_version: Patch version
            target_systems: Systems to patch
            cve_ids: CVE IDs addressed by patch
            kb_number: KB article number
            schedule: Deployment schedule
            
        Returns:
            Deployment ID
        """
        deployment_id = f"PATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Default to immediate deployment if no schedule
        if not schedule:
            schedule = datetime.now() + timedelta(minutes=15)
        
        # Create patch deployment
        deployment = PatchDeployment(
            deployment_id=deployment_id,
            patch_name=patch_name,
            patch_version=patch_version,
            kb_number=kb_number,
            cve_ids=cve_ids or [],
            target_systems=target_systems,
            deployment_method='wsus',
            deployment_schedule=schedule,
            maintenance_window=self.config['patch_management']['maintenance_windows'],
            requires_reboot=True,  # Would be determined by patch metadata
            test_results=None,
            deployment_status='pending',
            success_count=0,
            failure_count=0,
            created_at=datetime.now()
        )
        
        self.patch_deployments[deployment_id] = deployment
        self._cache_patch_deployment(deployment)
        
        # Schedule deployment
        if self.config['patch_management']['require_testing']:
            logger.info(f"Patch deployment {deployment_id} requires testing before production deployment")
        else:
            self._schedule_patch_deployment(deployment_id, schedule)
        
        logger.info(f"Created patch deployment: {deployment_id}")
        return deployment_id
    
    def remove_malware(self, malware_hash: str, affected_systems: List[str],
                      malware_name: str = None, incident_id: str = None) -> str:
        """
        Remove malware from affected systems
        
        Args:
            malware_hash: Hash of malware
            affected_systems: Systems to clean
            malware_name: Name of malware
            incident_id: Associated incident ID
            
        Returns:
            Remediation ID
        """
        remediation_id = f"MAL_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Determine malware family from hash (would use threat intelligence)
        malware_family = self._identify_malware_family(malware_hash)
        
        # Generate removal steps
        removal_steps = self._generate_malware_removal_steps(malware_family)
        
        # Identify persistence mechanisms
        persistence = self._identify_persistence_mechanisms(malware_family)
        
        # Create remediation task
        remediation = MalwareRemediation(
            remediation_id=remediation_id,
            malware_name=malware_name or f"Malware_{malware_hash[:8]}",
            malware_family=malware_family,
            malware_hash=malware_hash,
            affected_systems=affected_systems,
            removal_method='antivirus',
            removal_steps=removal_steps,
            persistence_mechanisms=persistence,
            cleanup_required=True,
            verification_scans=['full_scan', 'memory_scan', 'registry_scan'],
            status='pending',
            created_at=datetime.now(),
            completed_at=None
        )
        
        self.malware_remediations[remediation_id] = remediation
        self._cache_malware_remediation(remediation)
        
        # Execute removal
        self._execute_malware_removal(remediation_id)
        
        logger.info(f"Created malware remediation: {remediation_id}")
        return remediation_id
    
    def harden_system(self, target_system: str, hardening_profile: str = 'server',
                     compliance_framework: str = 'cis') -> str:
        """
        Apply hardening rules to system
        
        Args:
            target_system: System to harden
            hardening_profile: Profile to apply (server, workstation, etc.)
            compliance_framework: Compliance framework (cis, nist, etc.)
            
        Returns:
            Action ID
        """
        action_id = f"HARD_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Select applicable hardening rules
        applicable_rules = self._select_hardening_rules(target_system, hardening_profile, compliance_framework)
        
        # Generate remediation steps from rules
        remediation_steps = []
        for rule in applicable_rules:
            step = {
                'rule_id': rule.rule_id,
                'name': rule.name,
                'script': rule.remediation_script,
                'manual_steps': rule.manual_steps,
                'requires_testing': rule.requires_testing
            }
            remediation_steps.append(step)
        
        # Create mitigation action
        action = MitigationAction(
            action_id=action_id,
            incident_id=None,
            mitigation_type=MitigationType.CONFIG_HARDENING,
            priority=RemediationPriority.MEDIUM,
            status=MitigationStatus.PENDING,
            target_assets=[target_system],
            description=f"Apply {hardening_profile} hardening profile ({compliance_framework})",
            remediation_steps=remediation_steps,
            estimated_duration=len(applicable_rules) * 5,  # 5 minutes per rule
            actual_duration=None,
            success_criteria=[
                f"All {compliance_framework} controls applied",
                "Compliance scan passes",
                "No critical misconfigurations found"
            ],
            verification_steps=[
                "Run compliance scanner",
                "Verify security controls",
                "Check system functionality"
            ],
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            executed_by='system',
            results={},
            rollback_plan="Restore previous configuration from backup"
        )
        
        self.mitigation_actions[action_id] = action
        self._cache_mitigation_action(action)
        
        # Execute hardening
        if not self.config['hardening']['verify_before_apply']:
            self.execute_mitigation(action_id)
        
        logger.info(f"Created system hardening action: {action_id}")
        return action_id
    
    def rotate_credentials(self, affected_accounts: List[str], rotation_scope: str = 'password',
                          incident_id: str = None) -> str:
        """
        Rotate compromised credentials
        
        Args:
            affected_accounts: Accounts to rotate credentials for
            rotation_scope: Scope of rotation (password, api_key, certificate)
            incident_id: Associated incident ID
            
        Returns:
            Action ID
        """
        action_id = f"CRED_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Generate rotation steps
        rotation_steps = []
        for account in affected_accounts:
            step = {
                'account': account,
                'rotation_type': rotation_scope,
                'steps': [
                    f"Disable account {account}",
                    f"Generate new {rotation_scope}",
                    f"Update {rotation_scope} in all systems",
                    "Re-enable account",
                    "Verify access with new credentials",
                    "Revoke old credentials"
                ]
            }
            rotation_steps.append(step)
        
        # Create mitigation action
        action = MitigationAction(
            action_id=action_id,
            incident_id=incident_id,
            mitigation_type=MitigationType.CREDENTIAL_ROTATION,
            priority=RemediationPriority.HIGH,
            status=MitigationStatus.PENDING,
            target_assets=affected_accounts,
            description=f"Rotate {rotation_scope} for compromised accounts",
            remediation_steps=rotation_steps,
            estimated_duration=len(affected_accounts) * 10,
            actual_duration=None,
            success_criteria=[
                "All accounts have new credentials",
                "Old credentials revoked",
                "Access verified with new credentials",
                "No authentication failures"
            ],
            verification_steps=[
                "Test authentication with new credentials",
                "Verify old credentials don't work",
                "Check for any cached credentials"
            ],
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            executed_by='system',
            results={},
            rollback_plan="Restore previous credentials if new ones fail"
        )
        
        self.mitigation_actions[action_id] = action
        self._cache_mitigation_action(action)
        
        logger.info(f"Created credential rotation action: {action_id}")
        return action_id
    
    def assess_damage(self, incident_id: str, affected_systems: List[str],
                     compromised_accounts: List[str] = None) -> str:
        """
        Assess damage from security incident
        
        Args:
            incident_id: Incident to assess
            affected_systems: Systems involved in incident
            compromised_accounts: Compromised user accounts
            
        Returns:
            Assessment ID
        """
        assessment_id = f"ASSESS_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Perform damage assessment
        damage_analysis = self._analyze_incident_damage(incident_id, affected_systems)
        
        # Create assessment record
        assessment = DamageAssessment(
            assessment_id=assessment_id,
            incident_id=incident_id,
            affected_systems=affected_systems,
            compromised_accounts=compromised_accounts or [],
            data_accessed=damage_analysis.get('data_accessed', []),
            data_exfiltrated=damage_analysis.get('data_exfiltrated', False),
            estimated_data_loss=damage_analysis.get('data_loss', 'Unknown'),
            system_modifications=damage_analysis.get('modifications', []),
            persistence_found=damage_analysis.get('persistence', False),
            lateral_movement=damage_analysis.get('lateral_movement', False),
            estimated_dwell_time=damage_analysis.get('dwell_time', 'Unknown'),
            business_impact=damage_analysis.get('business_impact', 'Under assessment'),
            financial_impact=damage_analysis.get('financial_impact'),
            assessed_at=datetime.now(),
            assessed_by='system'
        )
        
        self.damage_assessments[assessment_id] = assessment
        self._cache_damage_assessment(assessment)
        
        logger.info(f"Completed damage assessment: {assessment_id}")
        return assessment_id
    
    def execute_mitigation(self, action_id: str) -> bool:
        """
        Execute mitigation action
        
        Args:
            action_id: Mitigation action to execute
            
        Returns:
            Success status
        """
        if action_id not in self.mitigation_actions:
            logger.error(f"Mitigation action {action_id} not found")
            return False
        
        action = self.mitigation_actions[action_id]
        
        # Update status
        action.status = MitigationStatus.IN_PROGRESS
        action.started_at = datetime.now()
        self._cache_mitigation_action(action)
        
        try:
            # Execute based on mitigation type
            if action.mitigation_type == MitigationType.PATCH_DEPLOYMENT:
                success = self._execute_patch_deployment(action)
            elif action.mitigation_type == MitigationType.MALWARE_REMOVAL:
                success = self._execute_malware_cleanup(action)
            elif action.mitigation_type == MitigationType.CONFIG_HARDENING:
                success = self._execute_hardening(action)
            elif action.mitigation_type == MitigationType.CREDENTIAL_ROTATION:
                success = self._execute_credential_rotation(action)
            elif action.mitigation_type == MitigationType.VULNERABILITY_FIX:
                success = self._execute_vulnerability_fix(action)
            else:
                logger.warning(f"Unsupported mitigation type: {action.mitigation_type}")
                success = False
            
            # Update status based on result
            if success:
                action.status = MitigationStatus.VERIFICATION_REQUIRED
                action.completed_at = datetime.now()
                action.actual_duration = int((action.completed_at - action.started_at).total_seconds() / 60)
                
                # Run verification if configured
                if self.config['remediation_policies']['verification_required']:
                    verified = self._verify_mitigation(action)
                    if verified:
                        action.status = MitigationStatus.COMPLETED
                    else:
                        action.status = MitigationStatus.PARTIALLY_COMPLETED
            else:
                action.status = MitigationStatus.FAILED
                
                # Auto-rollback if configured
                if self.config['remediation_policies']['auto_rollback_on_failure']:
                    self._rollback_mitigation(action)
            
            self._cache_mitigation_action(action)
            
            logger.info(f"Mitigation action {action_id} completed with status: {action.status.value}")
            return success
            
        except Exception as e:
            logger.error(f"Error executing mitigation action {action_id}: {e}")
            action.status = MitigationStatus.FAILED
            action.results['error'] = str(e)
            self._cache_mitigation_action(action)
            return False
    
    def get_mitigation_status(self, action_id: str = None) -> Dict[str, Any]:
        """
        Get mitigation status for action or all actions
        
        Args:
            action_id: Specific action ID, or None for all
            
        Returns:
            Status information
        """
        if action_id:
            if action_id not in self.mitigation_actions:
                return {'error': f'Action {action_id} not found'}
            
            action = self.mitigation_actions[action_id]
            return {
                'action_id': action_id,
                'type': action.mitigation_type.value,
                'status': action.status.value,
                'priority': action.priority.value,
                'target_assets': action.target_assets,
                'progress': self._calculate_action_progress(action),
                'started_at': action.started_at.isoformat() if action.started_at else None,
                'estimated_completion': self._estimate_completion_time(action),
                'results': action.results
            }
        else:
            # Return summary of all actions
            status_summary = defaultdict(int)
            for action in self.mitigation_actions.values():
                status_summary[action.status.value] += 1
            
            return {
                'total_actions': len(self.mitigation_actions),
                'status_summary': dict(status_summary),
                'in_progress': [
                    {
                        'action_id': a.action_id,
                        'type': a.mitigation_type.value,
                        'progress': self._calculate_action_progress(a)
                    }
                    for a in self.mitigation_actions.values()
                    if a.status == MitigationStatus.IN_PROGRESS
                ]
            }
    
    def get_mitigation_metrics(self, time_period: int = 30) -> Dict[str, Any]:
        """
        Get mitigation metrics for specified time period
        
        Args:
            time_period: Number of days to analyze
            
        Returns:
            Metrics dictionary
        """
        start_date = datetime.now() - timedelta(days=time_period)
        
        # Filter actions by time period
        recent_actions = [
            action for action in self.mitigation_actions.values()
            if action.created_at >= start_date
        ]
        
        if not recent_actions:
            return {'message': 'No mitigation actions in time period'}
        
        # Calculate metrics
        total_actions = len(recent_actions)
        completed_actions = len([a for a in recent_actions if a.status == MitigationStatus.COMPLETED])
        
        # Success rate by mitigation type
        type_stats = defaultdict(lambda: {'total': 0, 'completed': 0})
        
        for action in recent_actions:
            type_stats[action.mitigation_type.value]['total'] += 1
            if action.status == MitigationStatus.COMPLETED:
                type_stats[action.mitigation_type.value]['completed'] += 1
        
        # Calculate success rates
        for stats in type_stats.values():
            stats['success_rate'] = (stats['completed'] / stats['total'] * 100) if stats['total'] > 0 else 0
        
        # Average mitigation time
        completed_with_duration = [
            a for a in recent_actions
            if a.actual_duration is not None
        ]
        
        avg_duration = 0
        if completed_with_duration:
            avg_duration = sum(a.actual_duration for a in completed_with_duration) / len(completed_with_duration)
        
        # Vulnerability remediation stats
        vuln_remediations = len([
            a for a in recent_actions
            if a.mitigation_type == MitigationType.VULNERABILITY_FIX
        ])
        
        # Patch deployment stats
        patch_deployments = len([
            a for a in recent_actions
            if a.mitigation_type == MitigationType.PATCH_DEPLOYMENT
        ])
        
        metrics = {
            'time_period_days': time_period,
            'total_mitigation_actions': total_actions,
            'completed_actions': completed_actions,
            'completion_rate': (completed_actions / total_actions * 100) if total_actions > 0 else 0,
            'success_rate_by_type': dict(type_stats),
            'average_mitigation_time_minutes': round(avg_duration, 2),
            'vulnerability_remediations': vuln_remediations,
            'patch_deployments': patch_deployments,
            'malware_removals': len([a for a in recent_actions if a.mitigation_type == MitigationType.MALWARE_REMOVAL]),
            'systems_hardened': len([a for a in recent_actions if a.mitigation_type == MitigationType.CONFIG_HARDENING])
        }
        
        return metrics
    
    # Helper methods
    
    def _load_hardening_rules(self):
        """Load system hardening rules"""
        
        # Windows hardening rules
        windows_rules = [
            {
                'rule_id': 'WIN_001',
                'name': 'Disable SMBv1',
                'description': 'Disable SMBv1 protocol to prevent EternalBlue-type attacks',
                'category': 'os',
                'platform': 'windows',
                'severity': 'high',
                'cis_benchmark': 'CIS Windows Server 2019 v1.1.0 - 18.3.6',
                'configuration_check': 'Get-SmbServerConfiguration | Select EnableSMB1Protocol',
                'remediation_script': 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
                'manual_steps': None,
                'impact_assessment': 'Low - Legacy systems may require SMBv1',
                'requires_testing': True
            },
            {
                'rule_id': 'WIN_002',
                'name': 'Enable Windows Firewall',
                'description': 'Ensure Windows Firewall is enabled for all profiles',
                'category': 'network',
                'platform': 'windows',
                'severity': 'critical',
                'cis_benchmark': 'CIS Windows 10 v1.9.1 - 9.1.1',
                'configuration_check': 'Get-NetFirewallProfile -Profile Domain,Public,Private | Select Name,Enabled',
                'remediation_script': 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True',
                'manual_steps': None,
                'impact_assessment': 'Medium - May block required traffic if rules not configured',
                'requires_testing': True
            }
        ]
        
        # Linux hardening rules
        linux_rules = [
            {
                'rule_id': 'LIN_001',
                'name': 'Disable Root SSH Login',
                'description': 'Prevent direct root login via SSH',
                'category': 'os',
                'platform': 'linux',
                'severity': 'high',
                'cis_benchmark': 'CIS Ubuntu Linux 20.04 LTS v1.1.0 - 5.2.10',
                'configuration_check': 'grep "^PermitRootLogin" /etc/ssh/sshd_config',
                'remediation_script': None,
                'manual_steps': 'Edit /etc/ssh/sshd_config and set PermitRootLogin no, then restart sshd',
                'impact_assessment': 'Low - Requires use of sudo for administrative tasks',
                'requires_testing': True
            }
        ]
        
        # Create hardening rule objects
        for rule_data in windows_rules + linux_rules:
            rule = HardeningRule(
                rule_id=rule_data['rule_id'],
                name=rule_data['name'],
                description=rule_data['description'],
                category=rule_data['category'],
                platform=rule_data['platform'],
                severity=rule_data['severity'],
                cis_benchmark=rule_data['cis_benchmark'],
                configuration_check=rule_data['configuration_check'],
                remediation_script=rule_data['remediation_script'],
                manual_steps=rule_data['manual_steps'],
                impact_assessment=rule_data['impact_assessment'],
                requires_testing=rule_data['requires_testing']
            )
            
            self.hardening_rules[rule.rule_id] = rule
            self._cache_hardening_rule(rule)
    
    def _generate_remediation_steps(self, vuln: Vulnerability) -> List[Dict[str, Any]]:
        """Generate remediation steps for vulnerability"""
        
        steps = []
        
        # Step 1: Backup
        steps.append({
            'step': 1,
            'action': 'backup',
            'description': 'Backup affected systems before remediation',
            'required': True
        })
        
        # Step 2: Apply patch or workaround
        if vuln.patch_available:
            steps.append({
                'step': 2,
                'action': 'apply_patch',
                'description': f"Apply patch: {vuln.patch_details.get('patch_name') if vuln.patch_details else 'Available'}",
                'required': True
            })
        elif vuln.workaround:
            steps.append({
                'step': 2,
                'action': 'apply_workaround',
                'description': f"Apply workaround: {vuln.workaround}",
                'required': True
            })
        
        # Step 3: Verify
        steps.append({
            'step': 3,
            'action': 'verify',
            'description': 'Run vulnerability scanner to verify remediation',
            'required': True
        })
        
        # Step 4: Monitor
        steps.append({
            'step': 4,
            'action': 'monitor',
            'description': 'Monitor systems for any issues post-remediation',
            'required': False
        })
        
        return steps
    
    def _calculate_remediation_priority(self, vuln: Vulnerability) -> RemediationPriority:
        """Calculate remediation priority for vulnerability"""
        
        # Critical if CVSS >= 9.0 and exploit available
        if vuln.cvss_score >= 9.0 and vuln.exploit_available:
            return RemediationPriority.CRITICAL
        
        # High if CVSS >= 7.0 or exploit available
        elif vuln.cvss_score >= 7.0 or vuln.exploit_available:
            return RemediationPriority.HIGH
        
        # Medium if CVSS >= 4.0
        elif vuln.cvss_score >= 4.0:
            return RemediationPriority.MEDIUM
        
        # Low otherwise
        else:
            return RemediationPriority.LOW
    
    def _estimate_remediation_duration(self, vuln: Vulnerability, asset_count: int) -> int:
        """Estimate remediation duration in minutes"""
        
        base_time = 30  # Base time per system
        
        # Adjust for patch availability
        if vuln.patch_available:
            base_time = 20
        else:
            base_time = 60
        
        # Multiply by number of assets
        total_time = base_time * asset_count
        
        return total_time
    
    def _create_patch_deployment_from_vuln(self, vuln: Vulnerability, target_systems: List[str]):
        """Create patch deployment from vulnerability"""
        
        if not vuln.patch_details:
            return
        
        self.deploy_patch(
            patch_name=vuln.patch_details.get('patch_name', f"Patch for {vuln.cve_id}"),
            patch_version=vuln.patch_details.get('version', '1.0'),
            target_systems=target_systems,
            cve_ids=[vuln.cve_id] if vuln.cve_id else [],
            kb_number=vuln.patch_details.get('kb_number')
        )
    
    def _identify_malware_family(self, malware_hash: str) -> str:
        """Identify malware family from hash"""
        
        # This would integrate with threat intelligence
        # For now, return generic family
        return "Generic Malware"
    
    def _generate_malware_removal_steps(self, malware_family: str) -> List[str]:
        """Generate malware removal steps"""
        
        return [
            "Isolate infected system from network",
            "Run antivirus full scan",
            "Remove detected malware files",
            "Clean registry entries",
            "Remove persistence mechanisms",
            "Scan for additional malware",
            "Verify system integrity",
            "Reconnect to network and monitor"
        ]
    
    def _identify_persistence_mechanisms(self, malware_family: str) -> List[str]:
        """Identify persistence mechanisms for malware family"""
        
        common_persistence = [
            "Registry Run keys",
            "Scheduled tasks",
            "Windows services",
            "Startup folder",
            "WMI event subscriptions"
        ]
        
        return common_persistence
    
    def _execute_malware_removal(self, remediation_id: str):
        """Execute malware removal"""
        
        if remediation_id not in self.malware_remediations:
            return
        
        remediation = self.malware_remediations[remediation_id]
        
        # This would integrate with antivirus/EDR platforms
        logger.info(f"Simulating malware removal for {remediation.malware_name}")
        
        # Update status
        remediation.status = 'in_progress'
        self._cache_malware_remediation(remediation)
        
        # Simulate removal process
        time.sleep(2)
        
        remediation.status = 'completed'
        remediation.completed_at = datetime.now()
        self._cache_malware_remediation(remediation)
    
    def _select_hardening_rules(self, target_system: str, profile: str, framework: str) -> List[HardeningRule]:
        """Select applicable hardening rules"""
        
        # Determine platform
        platform = self._detect_system_platform(target_system)
        
        # Filter rules by platform and severity
        applicable_rules = [
            rule for rule in self.hardening_rules.values()
            if rule.platform == platform
        ]
        
        return applicable_rules
    
    def _detect_system_platform(self, system: str) -> str:
        """Detect system platform"""
        
        # This would actually detect the platform
        # For now, default to windows
        return 'windows'
    
    def _analyze_incident_damage(self, incident_id: str, affected_systems: List[str]) -> Dict[str, Any]:
        """Analyze damage from incident"""
        
        # This would perform actual forensic analysis
        # For now, return simulated analysis
        
        return {
            'data_accessed': ['file_server_share', 'database_records'],
            'data_exfiltrated': False,
            'data_loss': 'None detected',
            'modifications': [
                {'system': affected_systems[0], 'change': 'Registry modification'},
                {'system': affected_systems[0], 'change': 'File creation'}
            ],
            'persistence': True,
            'lateral_movement': False,
            'dwell_time': '< 24 hours',
            'business_impact': 'Low - no service disruption',
            'financial_impact': 5000.0
        }
    
    def _execute_patch_deployment(self, action: MitigationAction) -> bool:
        """Execute patch deployment"""
        
        # This would integrate with patch management systems
        logger.info(f"Simulating patch deployment for {len(action.target_assets)} systems")
        
        action.results['systems_patched'] = len(action.target_assets)
        action.results['method'] = 'wsus'
        
        return True
    
    def _execute_malware_cleanup(self, action: MitigationAction) -> bool:
        """Execute malware cleanup"""
        
        logger.info(f"Simulating malware cleanup for {len(action.target_assets)} systems")
        
        action.results['systems_cleaned'] = len(action.target_assets)
        action.results['threats_removed'] = 5
        
        return True
    
    def _execute_hardening(self, action: MitigationAction) -> bool:
        """Execute system hardening"""
        
        logger.info(f"Simulating system hardening for {len(action.target_assets)} systems")
        
        action.results['rules_applied'] = len(action.remediation_steps)
        action.results['compliance_score'] = 95.0
        
        return True
    
    def _execute_credential_rotation(self, action: MitigationAction) -> bool:
        """Execute credential rotation"""
        
        logger.info(f"Simulating credential rotation for {len(action.target_assets)} accounts")
        
        action.results['accounts_rotated'] = len(action.target_assets)
        action.results['rotation_method'] = 'automated'
        
        return True
    
    def _execute_vulnerability_fix(self, action: MitigationAction) -> bool:
        """Execute vulnerability fix"""
        
        logger.info(f"Simulating vulnerability fix for {len(action.target_assets)} systems")
        
        action.results['systems_remediated'] = len(action.target_assets)
        
        return True
    
    def _verify_mitigation(self, action: MitigationAction) -> bool:
        """Verify mitigation was successful"""
        
        # This would perform actual verification
        # For now, simulate successful verification
        
        logger.info(f"Verifying mitigation action {action.action_id}")
        
        action.results['verification_status'] = 'passed'
        action.results['verification_time'] = datetime.now().isoformat()
        
        return True
    
    def _rollback_mitigation(self, action: MitigationAction):
        """Rollback failed mitigation"""
        
        if not action.rollback_plan:
            logger.warning(f"No rollback plan available for action {action.action_id}")
            return
        
        logger.info(f"Rolling back mitigation action {action.action_id}")
        
        # This would execute actual rollback
        action.results['rollback_executed'] = True
        action.results['rollback_time'] = datetime.now().isoformat()
    
    def _calculate_action_progress(self, action: MitigationAction) -> float:
        """Calculate progress percentage for action"""
        
        if action.status == MitigationStatus.COMPLETED:
            return 100.0
        elif action.status == MitigationStatus.PENDING:
            return 0.0
        elif action.status == MitigationStatus.IN_PROGRESS:
            # Estimate based on time elapsed vs estimated duration
            if action.started_at and action.estimated_duration:
                elapsed = (datetime.now() - action.started_at).total_seconds() / 60
                progress = min((elapsed / action.estimated_duration) * 100, 95)
                return round(progress, 1)
        
        return 0.0
    
    def _estimate_completion_time(self, action: MitigationAction) -> Optional[str]:
        """Estimate completion time for action"""
        
        if action.status == MitigationStatus.COMPLETED:
            return None
        
        if action.status == MitigationStatus.IN_PROGRESS and action.started_at and action.estimated_duration:
            estimated_completion = action.started_at + timedelta(minutes=action.estimated_duration)
            return estimated_completion.isoformat()
        
        return None
    
    def _schedule_patch_deployment(self, deployment_id: str, schedule: datetime):
        """Schedule patch deployment for future execution"""
        
        def deploy():
            time_to_wait = (schedule - datetime.now()).total_seconds()
            if time_to_wait > 0:
                time.sleep(time_to_wait)
            
            logger.info(f"Executing scheduled patch deployment: {deployment_id}")
            # Would execute actual deployment here
        
        deployment_thread = threading.Thread(target=deploy)
        deployment_thread.daemon = True
        deployment_thread.start()
    
    # Database caching methods
    
    def _cache_mitigation_action(self, action: MitigationAction):
        """Cache mitigation action in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO mitigation_actions
            (action_id, incident_id, mitigation_type, priority, status,
             target_assets_json, description, remediation_steps_json,
             estimated_duration, actual_duration, success_criteria_json,
             verification_steps_json, created_at, started_at, completed_at,
             executed_by, results_json, rollback_plan)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action.action_id, action.incident_id, action.mitigation_type.value,
            action.priority.value, action.status.value,
            json.dumps(action.target_assets), action.description,
            json.dumps(action.remediation_steps), action.estimated_duration,
            action.actual_duration, json.dumps(action.success_criteria),
            json.dumps(action.verification_steps), action.created_at.isoformat(),
            action.started_at.isoformat() if action.started_at else None,
            action.completed_at.isoformat() if action.completed_at else None,
            action.executed_by, json.dumps(action.results), action.rollback_plan
        ))
        
        conn.commit()
        conn.close()
    
    def _cache_patch_deployment(self, deployment: PatchDeployment):
        """Cache patch deployment in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO patch_deployments
            (deployment_id, patch_name, patch_version, kb_number, cve_ids_json,
             target_systems_json, deployment_method, deployment_schedule,
             maintenance_window_json, requires_reboot, test_results_json,
             deployment_status, success_count, failure_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            deployment.deployment_id, deployment.patch_name, deployment.patch_version,
            deployment.kb_number, json.dumps(deployment.cve_ids),
            json.dumps(deployment.target_systems), deployment.deployment_method,
            deployment.deployment_schedule.isoformat(),
            json.dumps(deployment.maintenance_window), deployment.requires_reboot,
            json.dumps(deployment.test_results) if deployment.test_results else None,
            deployment.deployment_status, deployment.success_count,
            deployment.failure_count, deployment.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _cache_malware_remediation(self, remediation: MalwareRemediation):
        """Cache malware remediation in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO malware_remediations
            (remediation_id, malware_name, malware_family, malware_hash,
             affected_systems_json, removal_method, removal_steps_json,
             persistence_mechanisms_json, cleanup_required, verification_scans_json,
             status, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            remediation.remediation_id, remediation.malware_name,
            remediation.malware_family, remediation.malware_hash,
            json.dumps(remediation.affected_systems), remediation.removal_method,
            json.dumps(remediation.removal_steps),
            json.dumps(remediation.persistence_mechanisms),
            remediation.cleanup_required, json.dumps(remediation.verification_scans),
            remediation.status, remediation.created_at.isoformat(),
            remediation.completed_at.isoformat() if remediation.completed_at else None
        ))
        
        conn.commit()
        conn.close()
    
    def _cache_hardening_rule(self, rule: HardeningRule):
        """Cache hardening rule in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO hardening_rules
            (rule_id, name, description, category, platform, severity,
             cis_benchmark, configuration_check, remediation_script,
             manual_steps, impact_assessment, requires_testing)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.rule_id, rule.name, rule.description, rule.category,
            rule.platform, rule.severity, rule.cis_benchmark,
            rule.configuration_check, rule.remediation_script,
            rule.manual_steps, rule.impact_assessment, rule.requires_testing
        ))
        
        conn.commit()
        conn.close()
    
    def _cache_damage_assessment(self, assessment: DamageAssessment):
        """Cache damage assessment in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO damage_assessments
            (assessment_id, incident_id, affected_systems_json,
             compromised_accounts_json, data_accessed_json, data_exfiltrated,
             estimated_data_loss, system_modifications_json, persistence_found,
             lateral_movement, estimated_dwell_time, business_impact,
             financial_impact, assessed_at, assessed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.assessment_id, assessment.incident_id,
            json.dumps(assessment.affected_systems),
            json.dumps(assessment.compromised_accounts),
            json.dumps(assessment.data_accessed), assessment.data_exfiltrated,
            assessment.estimated_data_loss,
            json.dumps(assessment.system_modifications),
            assessment.persistence_found, assessment.lateral_movement,
            assessment.estimated_dwell_time, assessment.business_impact,
            assessment.financial_impact, assessment.assessed_at.isoformat(),
            assessment.assessed_by
        ))
        
        conn.commit()
        conn.close()


# Example usage
if __name__ == "__main__":
    # Initialize mitigation engine
    engine = ThreatMitigationEngine(data_dir="../../../")
    
    try:
        # Create sample vulnerability
        vuln = Vulnerability(
            vuln_id="VULN_001",
            cve_id="CVE-2021-44228",
            title="Apache Log4j Remote Code Execution",
            description="Log4Shell vulnerability",
            severity="Critical",
            cvss_score=10.0,
            affected_assets=["server_001", "server_002"],
            affected_software="Apache Log4j",
            affected_versions=["2.0-2.14.1"],
            exploit_available=True,
            patch_available=True,
            patch_details={'patch_name': 'Log4j 2.15.0', 'version': '2.15.0'},
            workaround="Disable JNDI lookups",
            discovered_at=datetime.now(),
            mitigated_at=None
        )
        engine.vulnerabilities[vuln.vuln_id] = vuln
        
        # Create vulnerability remediation
        action_id = engine.create_vulnerability_remediation("VULN_001")
        print(f"Created remediation action: {action_id}")
        
        # Execute remediation
        success = engine.execute_mitigation(action_id)
        print(f"Remediation {'successful' if success else 'failed'}")
        
        # Remove malware
        remediation_id = engine.remove_malware(
            malware_hash="abc123def456",
            affected_systems=["workstation_001"],
            malware_name="TrickBot"
        )
        print(f"Malware remediation: {remediation_id}")
        
        # Harden system
        hardening_id = engine.harden_system("server_001", "server", "cis")
        print(f"System hardening: {hardening_id}")
        
        # Rotate credentials
        cred_id = engine.rotate_credentials(["user001", "admin001"], "password")
        print(f"Credential rotation: {cred_id}")
        
        # Assess damage
        damage_id = engine.assess_damage("INC_001", ["server_001"])
        print(f"Damage assessment: {damage_id}")
        
        # Get metrics
        metrics = engine.get_mitigation_metrics(30)
        print(f"Mitigation metrics: {metrics}")
        
    except Exception as e:
        logger.error(f"Error in mitigation engine: {e}")
        raise
