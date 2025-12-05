# IRIS Case Management Integration Script

This directory contains a single integration script that exercises the IRIS case
management client end‑to‑end (cases, notes, assets, IOCs, tasks, timeline events,
and evidences).

## How to run

```bash
python tests/integrations/case_management/iris/test_iris_client.py
```

This will:
- Create a real case in your IRIS instance
- Add notes, assets, IOCs, tasks, timeline events and evidences to that case

## Configuration

The script expects a valid IRIS configuration in `config.json`:

```json
{
  "iris": {
    "base_url": "https://your-iris-server",
    "api_key": "your-api-key",
    "timeout_seconds": 30,
    "verify_ssl": false
  }
}
```

## Cleanup

To bulk‑delete IRIS cases created during testing, use the helper script
`tests/integrations/case_management/iris/delete_all_cases.py` (it will ask for
confirmation and can delete **all** cases, so use with care).
