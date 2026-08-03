import pytest
from pydantic import ValidationError as PydanticValidationError
from app.enums import ProjectStatus, Severity

from app.config import Settings
from app.pagination import PageParams
from app.schemas import LoginRequest, ProjectUpdate, UserCreate, VulnerabilityCreate


def test_login_rejects_empty_credentials_tc_auth_005() -> None:
    with pytest.raises(PydanticValidationError):
        LoginRequest(username="", password="")


def test_user_create_accepts_admin_role_tc_usr_004() -> None:
    payload = UserCreate(
        username="admin2",
        email="admin2@example.com",
        password="Admin1234!",
        role="admin",
    )

    assert payload.role.value == "admin"


def test_vulnerability_defaults_severity_to_info_tc_vuln_003() -> None:
    # Критичность не обязательна: без неё находка создаётся со значением "info".
    payload = VulnerabilityCreate(title="No severity", host_id=1)
    assert payload.severity == Severity.INFO


def test_vulnerability_rejects_invalid_severity_tc_vuln_004() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityCreate(title="Invalid severity", severity="extreme")


def test_project_update_rejects_unknown_status_tc_prj_009() -> None:
    with pytest.raises(PydanticValidationError):
        ProjectUpdate(status="invalid_status")


@pytest.mark.parametrize(
    "status",
    [
        ProjectStatus.ACTIVE,
        ProjectStatus.HANDOVER_TO_DEVELOPMENT,
        ProjectStatus.VULNERABILITY_RECHECK,
        ProjectStatus.COMPLETED,
        ProjectStatus.ARCHIVED,
    ],
)
def test_project_update_accepts_supported_statuses(status: ProjectStatus) -> None:
    payload = ProjectUpdate(status=status)

    assert payload.status == status


@pytest.mark.parametrize(("page", "size"), [(-1, 20), (1, 0)])
def test_page_params_reject_negative_page_and_zero_size_tc_pag_003_004(page: int, size: int) -> None:
    with pytest.raises(PydanticValidationError):
        PageParams(page=page, size=size)


def test_page_params_reject_excessive_size_tc_pag_005() -> None:
    with pytest.raises(PydanticValidationError):
        PageParams(page=1, size=10000)


def test_settings_reject_too_short_jwt_secret() -> None:
    with pytest.raises(PydanticValidationError):
        Settings(
            database_url="postgresql+asyncpg://user:password@localhost:5432/pcf_test",
            jwt_secret_key="short-secret",
            minio_endpoint="localhost:9000",
            minio_access_key="minio",
            minio_secret_key="minio",
            minio_bucket_name="pcf-files",
        )
