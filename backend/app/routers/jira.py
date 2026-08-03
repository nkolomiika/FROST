
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_admin, require_project_access
from app.models import User
from app.schemas import JiraConfigOut, JiraConfigUpsert, JiraIssueLinkOut, ProjectJiraLinkOut, ProjectJiraLinkUpsert
from app.services import JiraIntegrationService

router = APIRouter(tags=["jira"])


@router.get("/jira/config", response_model=JiraConfigOut | None)
async def get_jira_config(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> JiraConfigOut | None:
    return await JiraIntegrationService(db).get_config()


@router.put("/jira/config", response_model=JiraConfigOut)
async def upsert_jira_config(
    payload: JiraConfigUpsert,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> JiraConfigOut:
    return await JiraIntegrationService(db).upsert_config(payload.model_dump(), admin.id)


@router.get("/projects/{project_id}/jira-link", response_model=ProjectJiraLinkOut | None)
async def get_project_jira_link(
    project_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectJiraLinkOut | None:
    return await JiraIntegrationService(db).get_project_link(project_id)


@router.put("/projects/{project_id}/jira-link", response_model=ProjectJiraLinkOut)
async def upsert_project_jira_link(
    project_id: int,
    payload: ProjectJiraLinkUpsert,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectJiraLinkOut:
    return await JiraIntegrationService(db).upsert_project_link(project_id, payload.jira_project_key, admin.id)


@router.get("/projects/{project_id}/vulnerabilities/{vuln_id}/jira", response_model=JiraIssueLinkOut | None)
async def get_vulnerability_jira_link(
    project_id: int,
    vuln_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> JiraIssueLinkOut | None:
    _ = project_id
    return await JiraIntegrationService(db).get_issue_link(vuln_id)


@router.post("/projects/{project_id}/vulnerabilities/{vuln_id}/jira/export", response_model=JiraIssueLinkOut)
async def export_vulnerability_to_jira(
    project_id: int,
    vuln_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> JiraIssueLinkOut:
    return await JiraIntegrationService(db).export_vulnerability(project_id, vuln_id, current_user.id)
