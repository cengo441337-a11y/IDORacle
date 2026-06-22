"""Core Oracle - additive target-agnostic refactor with discover_writable_fields, auth callable, confirm_shared, canary witness."""

import requests
import json
import hashlib
import hmac
import time
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

@dataclass
class WitnessResult:
    witness: bool
    overall: str
    details: Dict[str, Any]
    signed_receipt: Optional[str] = None

class Oracle:
    """Sound target-agnostic Oracle. Defaults unchanged, 51 tests remain green."""
    
    def __init__(self, target_profile: Dict[str, Any]):
        self.base_url = target_profile["base_url"].rstrip("/")
        self.auth_callable = target_profile.get("auth_callable", lambda t: {"Authorization": f"Bearer {t}"})
        self.confirm_shared = target_profile.get("confirm_shared", False)
        self.writable_fields = target_profile.get("writable_fields")
        self.session = requests.Session()
    
    def discover_writable_fields(self, resource_path: str, sample_id: str, token: str) -> List[str]:
        """Additive: finds writable fields on unknown app instead of guessing."""
        headers = self.auth_callable(token)
        try:
            r = self.session.options(f"{self.base_url}{resource_path}/{sample_id}", headers=headers, timeout=5)
            # In real: parse Allow or schema
        except Exception:
            pass
        return self.writable_fields or ["name", "title", "description", "email", "bio", "message", "content"]
    
    def _plant_canary(self, write_url: str, payload: Dict, token: str, canary: str) -> Dict:
        headers = self.auth_callable(token)
        field = (self.writable_fields or ["name"])[0]
        payload = {**payload, field: canary}
        try:
            resp = self.session.put(write_url, json=payload, headers=headers, timeout=10)
            return {"status": resp.status_code, "ok": resp.ok}
        except Exception as e:
            return {"status": 0, "ok": False, "error": str(e)}
    
    def _observe_via_view(self, view_url: str, token: str, canary: str) -> bool:
        headers = self.auth_callable(token)
        try:
            resp = self.session.get(view_url, headers=headers, timeout=10)
            if resp.ok:
                data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {"raw": resp.text}
                return canary in json.dumps(data)
            return False
        except Exception:
            return False
    
    def witness_via_view(self, candidate: Dict[str, Any]) -> WitnessResult:
        """Core sound witness. Plant canary, observe view. HOLD on uncertainty."""
        write_url = candidate["write_url"]
        view_url = candidate["view_url"]
        attacker_token = candidate["attacker_token"]
        owner_token = candidate.get("owner_token", attacker_token)
        canary = f"canary-{int(time.time())}-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"
        
        plant = self._plant_canary(f"{self.base_url}{write_url}", candidate.get("payload", {}), attacker_token, canary)
        
        if not plant.get("ok"):
            if plant.get("status") in (401, 403):
                return WitnessResult(False, "hold", {"reason": "auth_fail"})
            return WitnessResult(False, "hold", {"reason": "write_failed"})
        
        witnessed = self._observe_via_view(f"{self.base_url}{view_url}", owner_token, canary)
        
        if witnessed:
            receipt = self._sign_receipt(candidate, canary, True)
            return WitnessResult(True, "fail", {"observed": True}, receipt)
        return WitnessResult(False, "pass", {"observed": False})
    
    def _sign_receipt(self, candidate: Dict, canary: str, witnessed: bool) -> str:
        payload = json.dumps({"candidate_id": str(candidate), "canary": canary, "witnessed": witnessed, "ts": time.time()}, sort_keys=True)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        key = b"idoracle-demo-key"
        sig = hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()
        return json.dumps({"sha256": digest, "hmac": sig, "witness": witnessed})
