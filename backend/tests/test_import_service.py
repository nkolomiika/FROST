from types import SimpleNamespace
from itertools import count as _id_count

_ids = _id_count(1)

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.enums import HostStatus
from app.exceptions import ValidationError
from app.services import ImportService


def _make_scalars_result(items: list[object]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = items
    return result


@pytest.mark.asyncio
async def test_find_matching_host_returns_exact_host() -> None:
    host_id = next(_ids)
    existing = SimpleNamespace(id=host_id, ip_address="10.0.0.5", hostname="api.local")
    host_data = SimpleNamespace(ip_address="10.0.0.5", hostname="api.local")
    db = AsyncMock()
    db.scalars = AsyncMock(return_value=_make_scalars_result([existing]))
    service = ImportService(db)

    matched = await service._find_matching_host(next(_ids), host_data)

    assert matched is existing


def test_merge_host_fields_only_fills_missing_values() -> None:
    host = SimpleNamespace(ip_address=None, hostname="api.local", status=HostStatus.UNKNOWN, notes=None)
    host_data = SimpleNamespace(ip_address="10.0.0.5", hostname="api.local", status=HostStatus.UP, notes="Imported from PCF")

    ImportService._merge_host_fields(host, host_data)

    assert host.ip_address == "10.0.0.5"
    assert host.hostname == "api.local"
    assert host.status == HostStatus.UP
    assert host.notes == "Imported from PCF"


def test_merge_endpoint_fields_preserves_existing_data_and_fills_missing() -> None:
    endpoint = SimpleNamespace(
        description=None,
        query_params=[],
        request_body=None,
        request_content_type=None,
        request_headers=[],
    )

    ImportService._merge_endpoint_fields(
        endpoint,
        {
            "description": "Imported endpoint",
            "query_params": [{"name": "role", "value": "admin"}],
            "request_body": "{\"ok\":true}",
            "request_content_type": "application/json",
            "request_headers": [{"name": "X-Test", "value": "1"}],
        },
    )

    assert endpoint.description == "Imported endpoint"
    assert endpoint.query_params == [{"name": "role", "value": "admin"}]
    assert endpoint.request_body == "{\"ok\":true}"
    assert endpoint.request_content_type == "application/json"
    assert endpoint.request_headers == [{"name": "X-Test", "value": "1"}]


def test_load_json_or_yaml_document_supports_yaml() -> None:
    parsed = ImportService._load_json_or_yaml_document(
        """
openapi: 3.0.0
paths:
  /health:
    get:
      summary: Check health
"""
    )

    assert parsed["openapi"] == "3.0.0"
    assert "/health" in parsed["paths"]


def test_load_json_or_yaml_document_supports_relaxed_swagger_text() -> None:
    parsed = ImportService._load_json_or_yaml_document(
        """
{
  swagger 2.0,
  basePath v1,
  paths {
    users{userId} {
      get {
        tags [
          users
        ],
        summary Get user,
        parameters [
          {
            name verbose,
            in query,
            required false,
            type string
          }
        ]
      }
    }
  }
}
"""
    )

    assert parsed["swagger"] == "2.0"
    assert parsed["basePath"] == "/v1"
    assert "/users/{userId}" in parsed["paths"]


def test_validate_openapi_payload_rejects_empty_bytes() -> None:
    with pytest.raises(ValidationError, match="пуст"):
        ImportService._validate_openapi_payload(b"")


def test_validate_openapi_payload_rejects_oversized_bytes() -> None:
    with pytest.raises(ValidationError, match="2 МБ"):
        ImportService._validate_openapi_payload(b"a" * (2 * 1024 * 1024 + 1))


def test_resolve_openapi_ref_supports_local_refs() -> None:
    document = {
        "paths": {
            "/users": {
                "$ref": "#/components/pathItems/UsersPath",
            }
        },
        "components": {
            "pathItems": {
                "UsersPath": {
                    "get": {
                        "$ref": "#/components/operations/ListUsers",
                    }
                }
            },
            "operations": {
                "ListUsers": {
                    "summary": "List users",
                }
            },
        },
    }

    path_item = ImportService._resolve_openapi_ref(document, document["paths"]["/users"])
    operation = ImportService._resolve_openapi_ref(document, path_item["get"])

    assert "$ref" in path_item["get"]
    assert operation["summary"] == "List users"


@pytest.mark.asyncio
async def test_import_openapi_skips_duplicate_and_adds_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = next(_ids)
    host_id = next(_ids)
    actor_id = next(_ids)
    host = SimpleNamespace(id=host_id, hostname="current.local", ip_address=None)
    existing_endpoint = SimpleNamespace(
        description=None,
        query_params=[],
        request_body=None,
        request_content_type=None,
        request_headers=[],
    )
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[host, existing_endpoint])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr("app.services.AuditService.log", AsyncMock())
    monkeypatch.setattr("app.services.ws_manager.broadcast", AsyncMock())
    service = ImportService(db)

    payload = b"""
openapi: 3.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      summary: List users
"""

    result = await service.import_openapi(project_id, host_id, payload, actor_id)

    assert result.endpoints_created == 0
    assert result.endpoints_skipped == 1
    assert result.spec_host == "api.example.com"
    assert result.errors
    assert existing_endpoint.description == "List users"
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_import_openapi_accepts_relaxed_swagger_text(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = next(_ids)
    host_id = next(_ids)
    actor_id = next(_ids)
    host = SimpleNamespace(id=host_id, hostname="current.local", ip_address=None)
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[host, None])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr("app.services.AuditService.log", AsyncMock())
    monkeypatch.setattr("app.services.ws_manager.broadcast", AsyncMock())
    service = ImportService(db)

    payload = b"""
{
  swagger 2.0,
  basePath v1,
  paths {
    users{userId} {
      get {
        tags [
          users
        ],
        summary Get user,
        parameters [
          {
            name verbose,
            in query,
            required false,
            type string
          }
        ]
      }
    }
  }
}
"""

    result = await service.import_openapi(project_id, host_id, payload, actor_id)

    assert result.endpoints_created == 1
    db.add.assert_called_once()
    created_endpoint = db.add.call_args.args[0]
    assert created_endpoint.path == "/v1/users/{userId}"
    assert created_endpoint.method == "GET"


def test_extract_openapi_request_details_handles_swagger2_body_with_definitions() -> None:
    document = {
        "swagger": "2.0",
        "consumes": ["application/json"],
        "definitions": {
            "Pet": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string", "example": "doggie"},
                    "status": {"type": "string", "enum": ["available", "sold"]},
                },
            }
        },
    }
    operation = {
        "parameters": [
            {"name": "body", "in": "body", "required": True, "schema": {"$ref": "#/definitions/Pet"}}
        ]
    }

    content_type, body = ImportService._extract_openapi_request_details(document, {}, operation)

    assert content_type == "application/json"
    assert body is not None
    assert "doggie" in body
    assert "available" in body


def test_extract_openapi_request_details_handles_swagger2_form_data() -> None:
    document = {"swagger": "2.0"}
    operation = {
        "consumes": ["application/x-www-form-urlencoded"],
        "parameters": [
            {"name": "name", "in": "formData", "type": "string", "example": "rex"},
            {"name": "status", "in": "formData", "type": "string", "default": "available"},
        ],
    }

    content_type, body = ImportService._extract_openapi_request_details(document, {}, operation)

    assert content_type == "application/x-www-form-urlencoded"
    assert body == "name=rex&status=available"


@pytest.mark.asyncio
async def test_import_openapi_skips_deprecated_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = next(_ids)
    host_id = next(_ids)
    actor_id = next(_ids)
    host = SimpleNamespace(id=host_id, hostname="api.local", ip_address=None)
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[host, None])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr("app.services.AuditService.log", AsyncMock())
    monkeypatch.setattr("app.services.ws_manager.broadcast", AsyncMock())
    service = ImportService(db)

    payload = b"""
openapi: 3.0.0
paths:
  /pet/findByTags:
    get:
      summary: Finds Pets by tags
      deprecated: true
  /pet/findByStatus:
    get:
      summary: Finds Pets by status
"""

    result = await service.import_openapi(project_id, host_id, payload, actor_id)

    assert result.endpoints_created == 1
    assert any("deprecated" in error.lower() for error in result.errors)
    created_endpoint = db.add.call_args.args[0]
    assert created_endpoint.path == "/pet/findByStatus"


@pytest.mark.asyncio
async def test_export_openapi_builds_document_from_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = next(_ids)
    host_id = next(_ids)
    host = SimpleNamespace(id=host_id, hostname="api.local", ip_address=None)
    endpoint = SimpleNamespace(
        path="/pet/{petId}",
        method=SimpleNamespace(value="GET"),
        description="Find pet by ID",
        query_params=[{"name": "verbose", "value": "true", "required": False, "description": "verbose mode"}],
        request_body=None,
        request_content_type=None,
        request_headers=[{"name": "X-Trace", "value": "abc"}],
    )
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=host)
    scalars_result = MagicMock()
    scalars_result.all.return_value = [endpoint]
    db.scalars = AsyncMock(return_value=scalars_result)
    service = ImportService(db)

    document = await service.export_openapi(project_id, host_id)

    assert document["openapi"] == "3.0.0"
    assert document["info"]["title"] == "api.local"
    operation = document["paths"]["/pet/{petId}"]["get"]
    assert operation["summary"] == "Find pet by ID"
    parameter_locations = {param["in"] for param in operation["parameters"]}
    assert {"query", "header"} <= parameter_locations
    assert any(p["name"] == "verbose" and p.get("example") == "true" for p in operation["parameters"])


def test_extract_openapi_query_params_uses_default_or_enum_value() -> None:
    document = {"swagger": "2.0"}
    operation = {
        "parameters": [
            {
                "name": "status",
                "in": "query",
                "type": "string",
                "enum": ["available", "pending", "sold"],
                "required": True,
            },
            {"name": "limit", "in": "query", "type": "integer", "default": 10},
        ]
    }

    params = ImportService._extract_openapi_query_params(document, {}, operation)

    assert {"name": "status", "value": "available", "required": True, "description": None} in params
    assert {"name": "limit", "value": "10", "required": False, "description": None} in params
