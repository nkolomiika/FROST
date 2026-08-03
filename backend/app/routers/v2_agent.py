
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import AgentTokenContext, require_agent_project_access, require_agent_scope
from app.enums import AssetType
from app.exceptions import NotFoundError
from app.models import AgentApiTokenProjectGrant, Host, Project
from app.pagination import PageParams, to_paginated_response
from app.schemas import HostOut, ProjectNoteCreate, ProjectNoteOut, ProjectNoteUpdate, ProjectOut, VulnerabilityCreate, VulnerabilityOut, VulnerabilityUpdate
from app.services import AssetService, ProjectNoteService, VulnerabilityService

router = APIRouter(tags=["agent-v2"])


@router.get("/projects", response_model=list[ProjectOut])
async def list_agent_projects(
    context: AgentTokenContext = Depends(require_agent_scope("projects:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectOut]:
    query = select(Project).order_by(Project.created_at.desc())
    if not context.all_projects:
        query = query.where(
            Project.id.in_(
                select(AgentApiTokenProjectGrant.project_id).where(AgentApiTokenProjectGrant.token_id == context.token_id)
            )
        )
    # Не шире прав создателя: не-админ видит только свои проекты (даже с all_projects).
    if not context.creator_is_admin:
        query = query.where(Project.id.in_(context.creator_project_ids or {-1}))
    projects = (await db.scalars(query)).all()
    return [ProjectOut.model_validate(project) for project in projects]


@router.get("/projects/{project_id}", response_model=ProjectOut)
async def get_agent_project(
    project_id: int,
    _scope: AgentTokenContext = Depends(require_agent_scope("projects:read")),
    project: Project = Depends(require_agent_project_access),
) -> ProjectOut:
    return ProjectOut.model_validate(project)


@router.get("/projects/{project_id}/hosts", response_model=dict)
async def list_agent_hosts(
    project_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=200),
    _scope: AgentTokenContext = Depends(require_agent_scope("assets:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    items, total = await AssetService(db).list_hosts(project_id, page, size, None)
    return to_paginated_response([HostOut.model_validate(item) for item in items], total, PageParams(page=page, size=size)).model_dump()


@router.get("/projects/{project_id}/hosts/{host_id}", response_model=dict)
async def get_agent_host(
    project_id: int,
    host_id: int,
    _scope: AgentTokenContext = Depends(require_agent_scope("assets:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await AssetService(db).get_host(project_id, host_id)


@router.get("/projects/{project_id}/notes", response_model=list[ProjectNoteOut])
async def list_agent_notes(
    project_id: int,
    _scope: AgentTokenContext = Depends(require_agent_scope("notes:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectNoteOut]:
    notes = await ProjectNoteService(db).list_notes(project_id)
    return [ProjectNoteOut.model_validate(note) for note in notes]


@router.get("/projects/{project_id}/notes/{note_id}", response_model=ProjectNoteOut)
async def get_agent_note(
    project_id: int,
    note_id: int,
    _scope: AgentTokenContext = Depends(require_agent_scope("notes:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).get_note(project_id, note_id)
    return ProjectNoteOut.model_validate(note)


@router.post("/projects/{project_id}/notes", response_model=ProjectNoteOut, status_code=status.HTTP_201_CREATED)
async def create_agent_note(
    project_id: int,
    payload: ProjectNoteCreate,
    context: AgentTokenContext = Depends(require_agent_scope("notes:write")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).create_note(project_id, payload.model_dump(), context.created_by)
    return ProjectNoteOut.model_validate(note)


@router.put("/projects/{project_id}/notes/{note_id}", response_model=ProjectNoteOut)
async def update_agent_note(
    project_id: int,
    note_id: int,
    payload: ProjectNoteUpdate,
    context: AgentTokenContext = Depends(require_agent_scope("notes:write")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).update_note(project_id, note_id, payload.model_dump(exclude_unset=True), context.created_by)
    return ProjectNoteOut.model_validate(note)


@router.get("/projects/{project_id}/hosts/{host_id}/vulnerabilities", response_model=dict)
async def list_agent_host_vulnerabilities(
    project_id: int,
    host_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=200),
    _scope: AgentTokenContext = Depends(require_agent_scope("vulns:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    items, total = await VulnerabilityService(db).list_for_host(project_id, host_id, page, size, None, None)
    return to_paginated_response([VulnerabilityOut.model_validate(item) for item in items], total, PageParams(page=page, size=size)).model_dump()


@router.get("/projects/{project_id}/hosts/{host_id}/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityOut)
async def get_agent_host_vulnerability(
    project_id: int,
    host_id: int,
    vulnerability_id: int,
    _scope: AgentTokenContext = Depends(require_agent_scope("vulns:read")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityOut:
    host_exists = await db.scalar(
        select(Host.id).where(and_(Host.id == host_id, Host.project_id == project_id))
    )
    if not host_exists:
        raise NotFoundError("Хост не принадлежит указанному проекту")
    bundle = await VulnerabilityService(db).get(project_id, vulnerability_id)
    host_links = [link for link in bundle["assets"] if link.asset_type == AssetType.HOST]
    if not any(link.asset_id == host_id for link in host_links):
        raise NotFoundError("Уязвимость не найдена на указанном хосте")
    return VulnerabilityOut.model_validate(bundle["vulnerability"])


@router.post("/projects/{project_id}/vulnerabilities", response_model=VulnerabilityOut, status_code=status.HTTP_201_CREATED)
async def create_agent_vulnerability(
    project_id: int,
    payload: VulnerabilityCreate,
    context: AgentTokenContext = Depends(require_agent_scope("vulns:write")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityOut:
    vuln = await VulnerabilityService(db).create(project_id, payload.model_dump(), context.created_by)
    return VulnerabilityOut.model_validate(vuln)


@router.put("/projects/{project_id}/vulnerabilities/{vuln_id}", response_model=VulnerabilityOut)
async def update_agent_vulnerability(
    project_id: int,
    vuln_id: int,
    payload: VulnerabilityUpdate,
    context: AgentTokenContext = Depends(require_agent_scope("vulns:write")),
    _project: Project = Depends(require_agent_project_access),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityOut:
    vuln = await VulnerabilityService(db).update(project_id, vuln_id, payload.model_dump(exclude_unset=True), context.created_by)
    return VulnerabilityOut.model_validate(vuln)
