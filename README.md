# Nuclei Discovery Tool

Template-based vulnerability scanner for security finding detection and evidence collection.

## Entity Extraction

The nuclei tool extracts the following entities to the GraphRAG knowledge graph:

### Entities

| Entity Type | Description | Key Fields |
|-------------|-------------|------------|
| **Finding** | Security vulnerabilities/issues | `title`, `severity`, `description`, `remediation`, `category`, `cve_ids`, `cvss_score`, `confidence` |
| **Endpoint** | Target URLs affected by findings | `url`, `method` |
| **Evidence** | Proof of vulnerability | `type`, `content`, `url` |

### Severity Levels

Findings are categorized by severity:
- `info` - Informational findings
- `low` - Low severity issues
- `medium` - Medium severity vulnerabilities
- `high` - High severity vulnerabilities
- `critical` - Critical security flaws

### Relationships

| Relationship Type | From | To | Description |
|-------------------|------|------|-------------|
| `AFFECTS` | Finding | Endpoint | Finding affects a target endpoint |
| `HAS_EVIDENCE` | Finding | Evidence | Finding has supporting evidence |

### Entity ID Generation

Entity IDs are deterministically generated using SHA1-based UUIDs for idempotency:

- **Finding**: `uuid5(OID, "finding:nuclei:{template_id}:{host}:{matched_at}")`
- **Endpoint**: `uuid5(OID, "endpoint:{url}")`
- **Evidence**: `uuid5(OID, "evidence:{finding_id}:{index}")`

## Example Graph Structure

```
[Finding: SQL Injection (CVE-2021-xxxxx)]
    ├── AFFECTS → [Endpoint: https://example.com/login]
    └── HAS_EVIDENCE → [Evidence: extracted SQL error]

[Finding: Missing Security Headers]
    └── AFFECTS → [Endpoint: https://example.com/]
```

## Provenance

All relationships include provenance properties:

- `discovered_by`: `"nuclei"`
- `discovered_at`: Unix timestamp (milliseconds)
- `mission_run_id`: Mission context identifier

AFFECTS relationships include additional context:
- `severity`: Finding severity level
- `confidence`: Detection confidence (0.0-1.0)
- `category`: Finding category tags

HAS_EVIDENCE relationships include:
- `evidence_type`: Type of evidence (extracted_data, match_location)

## Metadata

Extraction metadata includes:

- `finding_count`: Number of findings extracted
- `evidence_count`: Number of evidence items extracted
- `endpoint_count`: Number of unique endpoints
- `total_requests`: Total HTTP requests made
- `total_matches`: Total template matches
- `templates_loaded`: Number of templates loaded
- `templates_executed`: Number of templates executed
- `scan_duration`: Total scan duration in seconds
