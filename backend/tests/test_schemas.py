import pytest
from pydantic import ValidationError as PydanticValidationError

from app.schemas import (
    EndpointCreate,
    HostCreate,
    PcfImportPayload,
    PortCreate,
    UserCreate,
    VulnerabilityCreate,
    VulnerabilityWorkflowStep,
    VulnerabilityStatusPatch,
)


def test_user_create_rejects_short_password_tc_usr_008() -> None:
    with pytest.raises(PydanticValidationError):
        UserCreate(
            username="new_user",
            email="new_user@example.com",
            password="short",
        )


def test_host_create_requires_ip_or_hostname_tc_host_003() -> None:
    with pytest.raises(PydanticValidationError):
        HostCreate(notes="Host without ip and hostname")


def test_host_create_accepts_hostname_only_tc_host_002() -> None:
    payload = HostCreate(hostname="target.example.com")

    assert payload.hostname == "target.example.com"
    assert payload.ip_address is None


@pytest.mark.parametrize("port", [1, 65535])
def test_port_create_accepts_boundary_values_tc_port_003_004(port: int) -> None:
    payload = PortCreate(ip_address_id=1, port_number=port)

    assert payload.port_number == port


@pytest.mark.parametrize("port", [0, 65536])
def test_port_create_rejects_out_of_range_values_tc_port_005_006(port: int) -> None:
    with pytest.raises(PydanticValidationError):
        PortCreate(port_number=port)


def test_endpoint_requires_path_tc_ep_003() -> None:
    with pytest.raises(PydanticValidationError):
        EndpointCreate(method="GET")


def test_pcf_import_host_requires_ip_or_hostname() -> None:
    with pytest.raises(PydanticValidationError):
        PcfImportPayload.model_validate({"hosts": [{"status": "unknown"}]})


def test_pcf_import_rejects_invalid_port_protocol() -> None:
    with pytest.raises(PydanticValidationError):
        PcfImportPayload.model_validate(
            {
                "hosts": [
                    {
                        "hostname": "target.local",
                        "ports": [{"port_number": 443, "protocol": "icmp"}],
                    }
                ]
            }
        )


def test_pcf_import_endpoint_requires_path_or_request_raw() -> None:
    with pytest.raises(PydanticValidationError):
        PcfImportPayload.model_validate({"hosts": [{"hostname": "target.local", "endpoints": [{"method": "GET"}]}]})


def test_vulnerability_rejects_invalid_cvss_score_tc_vuln_005() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityCreate(
            title="CVSS overflow",
            severity="high",
            cvss_score=10.1,
        )


def test_vulnerability_rejects_cvss_31_version() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityCreate(
            host_id=1,
            title="Legacy CVSS",
            severity="high",
            cvss_version="3.1",
        )


def test_vulnerability_rejects_invalid_status_patch_tc_vuln_010() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityStatusPatch(status="closed")


def test_vulnerability_accepts_structured_workflow_steps() -> None:
    payload = VulnerabilityCreate(
        host_id=1,
        title="Stored XSS",
        severity="high",
        workflow_steps=[
            VulnerabilityWorkflowStep(
                id="step-1",
                description="Перейти в профиль и открыть форму комментария",
                image_file_ids=[],
            )
        ],
    )

    assert len(payload.workflow_steps) == 1
    assert payload.workflow_steps[0].description == "Перейти в профиль и открыть форму комментария"
