{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.org/personal-agent-runtime/appliance_profile.schema.json",
  "title": "Personal Agent Runtime Appliance Profile",
  "type": "object",
  "required": ["appliance_version", "profile_id", "transport", "authority_model", "services"],
  "properties": {
    "appliance_version": {"const": "0.9"},
    "profile_id": {"type": "string", "minLength": 1},
    "transport": {"enum": ["unix-domain-socket", "localhost"]},
    "authority_model": {
      "type": "object",
      "required": [
        "planner_may_sign", "review_signer_may_execute", "gate_may_execute",
        "executor_may_change_registry", "verifier_may_execute", "execution_requires_gate_permit"
      ],
      "properties": {
        "planner_may_sign": {"const": false},
        "review_signer_may_execute": {"const": false},
        "gate_may_execute": {"const": false},
        "executor_may_change_registry": {"const": false},
        "verifier_may_execute": {"const": false},
        "execution_requires_gate_permit": {"const": true}
      },
      "additionalProperties": false
    },
    "services": {
      "type": "object",
      "required": ["planner", "review_signer", "gate", "executor", "verifier"],
      "properties": {
        "planner": {"$ref": "#/$defs/service"},
        "review_signer": {"$ref": "#/$defs/service"},
        "gate": {"$ref": "#/$defs/service"},
        "executor": {"$ref": "#/$defs/service"},
        "verifier": {"$ref": "#/$defs/service"}
      },
      "additionalProperties": false
    },
    "public_trust_store": {"type": "string"}
  },
  "$defs": {
    "service": {
      "type": "object",
      "required": ["socket", "state_dir"],
      "properties": {
        "socket": {"type": "string"},
        "state_dir": {"type": "string"},
        "private_key": {"type": "string"},
        "private_keys": {"type": "array", "items": {"type": "string"}},
        "subject": {"type": "string"},
        "roles": {"type": "array", "items": {"type": "string"}},
        "registry": {"type": "string"},
        "trust_store": {"type": "string"},
        "review_replay_db": {"type": "string"},
        "permit_replay_db": {"type": "string"},
        "permit_ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
        "sandbox_root": {"type": "string"},
        "chain_state": {"type": "string"}
      },
      "additionalProperties": true
    }
  },
  "additionalProperties": true
}
