"""Scanner — раздел рекон-инструментов поверх фермы (kind-задачи в host_farm_jobs).

Каждый инструмент ставит фоновую задачу (create_job) и опрашивается по job_id,
как и остальные фермы. Отдельный роутер, чтобы «scanner» был самостоятельным
разделом API и UI.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.farm import PortScanFarmService, ReverseFarmService, SubdomainFarmService, enqueue_job
from app.models import User
from app.schemas import (
    PortScanJobOut,
    PortScanRequest,
    ReverseFarmJobOut,
    ReverseFarmRequest,
    SubFarmJobOut,
    SubFarmRequest,
)

router = APIRouter(tags=["scanner"])


@router.post(
    "/projects/{project_id}/scanner/subdomains",
    response_model=SubFarmJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_subdomain_scan(
    project_id: int,
    payload: SubFarmRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> SubFarmJobOut:
    """Снимает корни (или домены проекта) и ставит раскрытие поддоменов в фон."""
    job = await SubdomainFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return SubFarmJobOut.model_validate(job)


@router.get(
    "/projects/{project_id}/scanner/subdomains/jobs/{job_id}",
    response_model=SubFarmJobOut,
)
async def get_subdomain_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> SubFarmJobOut:
    """Статус задачи раскрытия поддоменов. Задачу чужого kind не отдаёт."""
    job = await SubdomainFarmService(db).get_job(project_id, job_id)
    return SubFarmJobOut.model_validate(job)


@router.post(
    "/projects/{project_id}/scanner/port-scan",
    response_model=PortScanJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_port_scan(
    project_id: int,
    payload: PortScanRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> PortScanJobOut:
    """Снимает цели (или хосты проекта) и ставит nmap-скан портов в фон."""
    job = await PortScanFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return PortScanJobOut.model_validate(job)


@router.get(
    "/projects/{project_id}/scanner/port-scan/jobs/{job_id}",
    response_model=PortScanJobOut,
)
async def get_port_scan_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> PortScanJobOut:
    """Статус задачи скана портов. Задачу чужого kind не отдаёт."""
    job = await PortScanFarmService(db).get_job(project_id, job_id)
    return PortScanJobOut.model_validate(job)


@router.post(
    "/projects/{project_id}/scanner/reverse",
    response_model=ReverseFarmJobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_reverse_scan(
    project_id: int,
    payload: ReverseFarmRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ReverseFarmJobOut:
    """Берёт IP (или все адреса проекта) и ставит обратный резолв с раскрытием
    хостов в фон. Этот кросс-рекон намеренно НЕ делается при обычном «Add IPs»."""
    job = await ReverseFarmService(db).create_job(project_id, payload.raw, current_user.id)
    enqueue_job(job, background_tasks)
    return ReverseFarmJobOut.model_validate(job)


@router.get(
    "/projects/{project_id}/scanner/reverse/jobs/{job_id}",
    response_model=ReverseFarmJobOut,
)
async def get_reverse_scan_job(
    project_id: int,
    job_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ReverseFarmJobOut:
    """Статус задачи обратного резолва. Задачу чужого kind не отдаёт."""
    job = await ReverseFarmService(db).get_job(project_id, job_id)
    return ReverseFarmJobOut.model_validate(job)
