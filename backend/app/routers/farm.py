from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.farm import HostFarmService, IpFarmService, JsFarmService, enqueue_job
from app.models import User
from app.schemas import (
    HostFarmJobOut,
    HostFarmRequest,
    IpFarmJobOut,
    IpFarmRequest,
    JsFarmJobOut,
    JsFarmRequest,
)

router = APIRouter(tags=["recon-farm"])


@router.post(
    "/projects/{project_id}/host-farm",
    response_model=HostFarmJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_host_farm(
    project_id: int,
    payload: HostFarmRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> HostFarmJobOut:
    """Парсит вставленный список (синхронно) и ставит пробив в фон."""
    job = await HostFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return HostFarmJobOut.model_validate(job)


@router.get("/projects/{project_id}/host-farm/jobs/{job_id}", response_model=HostFarmJobOut)
async def get_host_farm_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> HostFarmJobOut:
    """Статус фоновой задачи фермы хостов (фронт опрашивает до status=done)."""
    job = await HostFarmService(db).get_job(project_id, job_id)
    return HostFarmJobOut.model_validate(job)


@router.post(
    "/projects/{project_id}/ip-farm",
    response_model=IpFarmJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_ip_farm(
    project_id: int,
    payload: IpFarmRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> IpFarmJobOut:
    """Парсит вставленный список адресов и ставит обратный резолв + пробив в фон."""
    job = await IpFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return IpFarmJobOut.model_validate(job)


@router.get("/projects/{project_id}/ip-farm/jobs/{job_id}", response_model=IpFarmJobOut)
async def get_ip_farm_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> IpFarmJobOut:
    """Статус фоновой задачи фермы IP. Задачу чужого kind не отдаёт."""
    job = await IpFarmService(db).get_job(project_id, job_id)
    return IpFarmJobOut.model_validate(job)


@router.post(
    "/projects/{project_id}/js-farm",
    response_model=JsFarmJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_js_farm(
    project_id: int,
    payload: JsFarmRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> JsFarmJobOut:
    """Снимает домены проекта (или из payload.raw) и ставит скан JS в фон."""
    job = await JsFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return JsFarmJobOut.model_validate(job)


@router.get("/projects/{project_id}/js-farm/jobs/{job_id}", response_model=JsFarmJobOut)
async def get_js_farm_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> JsFarmJobOut:
    """Статус фоновой задачи фермы JS. Задачу чужого kind не отдаёт."""
    job = await JsFarmService(db).get_job(project_id, job_id)
    return JsFarmJobOut.model_validate(job)
