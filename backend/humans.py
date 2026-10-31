"""
Human approver interface (UI-APP-*). Agents never import this module and never hold approver keys.
In demo/test mode the approver dev keys stand in for people.
"""

from __future__ import annotations

from typing import Any, Dict, List

from eth_account.messages import encode_typed_data

from backend.common.chain import Chain, ChainRevert

STATUS = ["None", "Pending", "Approved", "Rejected", "Expired", "Executed", "Cancelled"]


class HumanApprover:
    def __init__(self, chain: Chain, org: str):
        self.chain, self.org = chain, org

    def _rid(self, request_id: str) -> bytes:
        return bytes.fromhex(request_id.replace("0x", ""))

    def approve(self, request_id: str, approver: int) -> dict:
        return self.chain.transact("ApprovalGate", "approve", [self._rid(request_id)], f"{self.org}/approver{approver}")

    def reject(self, request_id: str, approver: int) -> dict:
        return self.chain.transact("ApprovalGate", "reject", [self._rid(request_id)], f"{self.org}/approver{approver}")

    def approve_with_sigs(self, request_id: str, approvers: List[int], relayer: str = "deployer") -> dict:
        domain = {"name": "ApprovalGate", "version": "1", "chainId": self.chain.chain_id, "verifyingContract": self.chain.contracts["ApprovalGate"].address}
        types = {"Vote": [{"name": "requestId", "type": "bytes32"}, {"name": "approve", "type": "bool"}]}
        rid = self._rid(request_id)
        addrs, sigs = [], []
        for i in approvers:
            key = f"{self.org}/approver{i}"
            sigs.append(self.chain.sign_typed(key, domain, types, {"requestId": rid, "approve": True}))
            addrs.append(self.chain.accounts[key].address)
        return self.chain.transact("ApprovalGate", "approveWithSigs", [rid, addrs, sigs], relayer)

    def view(self, request_id: str) -> Dict[str, Any]:
        """Everything an approver needs to see (UI-APP-02)."""
        c = self.chain
        rid = self._rid(request_id)
        r = c.call("ApprovalGate", "getRequest", rid)
        voters, flags = c.call("ApprovalGate", "getSnapshotApprovers", rid)
        votes = [{"approver": a, "safety_officer": f, "voted": bool(c.call("ApprovalGate", "hasVoted", rid, a))} for a, f in zip(voters, flags)]
        return {
            "request_id": request_id, "org": self.org, "plan_hash": "0x" + bytes(r[1]).hex(), "critic_verdict_digest": "0x" + bytes(r[2]).hex(),
            "impact": ["LOW", "MEDIUM", "HIGH"][int(r[3])], "status": STATUS[int(r[4])], "expiry": int(r[5]), "required": int(r[6]), "approvals": int(r[7]),
            "rejections": int(r[8]), "safety_approved": bool(r[9]), "needs_safety_officer": bool(r[10]), "approvers": votes,
            "seconds_left": max(int(r[5]) - c.block_timestamp(), 0),
        }
