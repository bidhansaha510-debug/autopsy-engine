from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.models import ConfigChange, Deployment, Evidence
from backend.models.base import generate_uuid
from backend.normalization.normalizer import normalize_event_payload, normalize_timestamp
from backend.core.security import sanitize_text


class ConfigChangeIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "CONFIG"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "config-management",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        service = raw_payload.get("service") or "system"
        key = raw_payload.get("config_key") or raw_payload.get("key") or "unknown_param"
        old_val = str(raw_payload.get("old_value", ""))
        new_val = str(raw_payload.get("new_value", ""))
        changed_by = raw_payload.get("changed_by") or "operator"
        reason = raw_payload.get("reason")

        ts, _ = normalize_timestamp(raw_payload.get("changed_at"))

        config_rec = ConfigChange(
            id=generate_uuid(),
            service=service,
            config_key=key,
            old_value=old_val,
            new_value=new_val,
            changed_at=ts,
            changed_by=sanitize_text(changed_by),
            reason=sanitize_text(reason),
            environment=environment,
            metadata_json=raw_payload.get("metadata", {}),
        )
        db.add(config_rec)

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        # Config changes are prime evidence candidates!
        evidence = None
        if incident_id:
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-CFG")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=ts,
                evidence_type="CONFIG",
                source=source,
                entity=f"{service}.{key}",
                content={
                    "service": service,
                    "config_key": key,
                    "old_value": old_val,
                    "new_value": new_val,
                    "changed_by": changed_by,
                    "reason": reason,
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=[config_rec])


class DeploymentIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "DEPLOYMENT"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "ci-cd-pipeline",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        service = raw_payload.get("service") or "unknown-service"
        version = raw_payload.get("version") or "v1.0.0"
        commit_sha = raw_payload.get("commit_sha") or raw_payload.get("commit")
        deployed_by = raw_payload.get("deployed_by") or "ci-runner"
        status = raw_payload.get("status") or "SUCCESS"
        changelog = raw_payload.get("changelog")

        ts, _ = normalize_timestamp(raw_payload.get("deployed_at"))

        deploy_rec = Deployment(
            id=generate_uuid(),
            service=service,
            version=version,
            commit_sha=commit_sha,
            deployed_at=ts,
            deployed_by=sanitize_text(deployed_by),
            status=status,
            changelog=sanitize_text(changelog),
            environment=environment,
            metadata_json=raw_payload.get("metadata", {}),
        )
        db.add(deploy_rec)

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        evidence = None
        if incident_id:
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-DEP")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=ts,
                evidence_type="DEPLOYMENT",
                source=source,
                entity=f"{service}:{version}",
                content={
                    "service": service,
                    "version": version,
                    "commit_sha": commit_sha,
                    "status": status,
                    "deployed_by": deployed_by,
                    "changelog": changelog,
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=[deploy_rec])
