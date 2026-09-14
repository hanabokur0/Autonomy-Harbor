{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.invalid/personal-agent-runtime/capability-registry.schema.json",
  "title": "CapabilityRegistry",
  "type": "object",
  "additionalProperties": false,
  "required": ["registry_id", "version", "grants"],
  "properties": {
    "registry_id": {"type": "string", "minLength": 1},
    "version": {"type": "string", "minLength": 1},
    "grants": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["grant_id", "capability", "effect", "actions", "resources"],
        "properties": {
          "grant_id": {"type": "string", "minLength": 1},
          "capability": {"type": "string", "minLength": 1},
          "effect": {"enum": ["ALLOW", "REVIEW", "DENY"]},
          "actions": {"type": "array", "minItems": 1, "items": {"type": "string"}},
          "resources": {"type": "array", "minItems": 1, "items": {"type": "string"}},
          "issued_by": {"type": "string"},
          "note": {"type": "string"}
        }
      }
    }
  }
}
