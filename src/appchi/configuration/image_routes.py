"""Uploaded images for dashboard image panels (REV-62).

Uploads are immutable and stored once per tenant and SHA-256. A dashboard save marks
the images its panels reference as used; used images are kept like retained history.
Never-used uploads are the only rows removed: each upload deletes a bounded batch of
the tenant's older ones under the tenant configuration-reference guard, so no worker
is needed (REV-34) and no save can race the deletion.
"""

from hashlib import sha256
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from appchi.access import authorize
from appchi.configuration.images import (
    TENANT_QUOTA,
    UNUSED_AFTER_HOURS,
    UNUSED_BATCH,
    InvalidImage,
    inspect,
)
from appchi.models import uuid_string
from appchi.shared.errors import AppError
from appchi.shared.transactions import command_result, save_result

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])
# Served bytes never run as a document, whatever a file claims to be.
SERVED = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox; default-src 'none'",
    "Content-Disposition": "inline",
    "Cache-Control": "private, no-cache",
}


def _identifiers(*values):
    try:
        for value in values:
            uuid_string(value)
    except ValueError:
        raise AppError("invalid_identifier", "Canonical UUID required.") from None


def _image(row):
    return {
        "id": str(row["id"]),
        "media_type": row["media_type"],
        "width": row["width"],
        "height": row["height"],
        "byte_size": row["byte_size"],
    }


@router.post(
    "/dashboard-images",
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                media: {"schema": {"type": "string", "format": "binary"}}
                for media in ("image/png", "image/jpeg", "image/gif", "image/webp")
            },
        },
        "parameters": [
            {
                "name": "Idempotency-Key",
                "in": "header",
                "required": True,
                "schema": {"type": "string", "format": "uuid"},
            }
        ],
    },
)
async def upload_image(tenant_id: str, request: Request):
    """Store a PNG, JPEG, GIF or WebP file of at most 5 MiB for image panels."""
    _identifiers(tenant_id)
    data = await request.body()
    command_id = request.headers.get("idempotency-key", "")
    try:
        uuid_string(command_id)
    except ValueError:
        raise AppError("invalid_command", "A UUID Idempotency-Key header is required.", 422) from None
    digest = sha256(data).digest()
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        # Inspect only once the caller may upload, so anonymous bodies are never read.
        try:
            media, width, height = inspect(data)
        except InvalidImage as exc:
            raise AppError("invalid_image", str(exc), 422) from None
        scope = f"{tenant_id}:{actor['id']}:dashboard_images:upload"
        prior, fingerprint = command_result(conn, scope, command_id, {"sha256": digest.hex()})
        if prior is not None:
            return JSONResponse(prior, status_code=200)
        conn.execute(
            "SELECT tenant_id FROM tenant_configuration_guard WHERE tenant_id=%s FOR UPDATE",
            (tenant_id,),
        )
        conn.execute(
            """DELETE FROM dashboard_images WHERE tenant_id=%s AND id IN (
                SELECT id FROM dashboard_images WHERE tenant_id=%s AND first_used_at IS NULL
                AND created_at < clock_timestamp() - make_interval(hours => %s)
                ORDER BY created_at LIMIT %s)""",
            (tenant_id, tenant_id, UNUSED_AFTER_HOURS, UNUSED_BATCH),
        )
        existing = conn.execute(
            "SELECT id,media_type,width,height,byte_size FROM dashboard_images WHERE tenant_id=%s AND sha256=%s",
            (tenant_id, digest),
        ).fetchone()
        status = 200
        if existing:
            row = existing
        else:
            stored = conn.execute(
                "SELECT coalesce(sum(byte_size),0) AS total FROM dashboard_images WHERE tenant_id=%s",
                (tenant_id,),
            ).fetchone()["total"]
            if stored + len(data) > TENANT_QUOTA:
                raise AppError(
                    "image_quota_exceeded",
                    "This tenant's images use the 500 MiB allowed. Remove image panels to free space.",
                    409,
                )
            row = conn.execute(
                """INSERT INTO dashboard_images(id,tenant_id,sha256,media_type,width,height,byte_size,bytes,created_at,created_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,clock_timestamp(),%s)
                RETURNING id,media_type,width,height,byte_size""",
                (uuid4(), tenant_id, digest, media, width, height, len(data), data, actor["id"]),
            ).fetchone()
            status = 201
        result = save_result(conn, scope, command_id, fingerprint, {"data": _image(row), "meta": {}}, status)
    return JSONResponse(result, status_code=status)


@router.get(
    "/dashboard-images/{image_id}",
    response_class=Response,
    responses={
        200: {
            "content": {
                media: {"schema": {"type": "string", "format": "binary"}}
                for media in ("image/png", "image/jpeg", "image/gif", "image/webp")
            }
        },
        304: {"description": "The cached image is current."},
    },
)
def read_image(tenant_id: str, image_id: str, request: Request):
    """Serve an uploaded image to anyone who can read the tenant."""
    _identifiers(tenant_id, image_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        row = conn.execute(
            "SELECT sha256,media_type,bytes FROM dashboard_images WHERE tenant_id=%s AND id=%s",
            (tenant_id, image_id),
        ).fetchone()
    if not row:
        raise AppError("not_found", "Resource unavailable.", 404)
    etag = f'"{bytes(row["sha256"]).hex()}"'
    headers = {**SERVED, "ETag": etag}
    if etag in [tag.strip() for tag in request.headers.get("if-none-match", "").split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(bytes(row["bytes"]), media_type=row["media_type"], headers=headers)


def lock_images(conn, tenant, image_ids):
    """Lock referenced uploads in a stable order; any missing image fails the save."""
    for image_id in sorted(image_ids):
        if not conn.execute(
            "SELECT 1 FROM dashboard_images WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, image_id),
        ).fetchone():
            raise AppError("image_unavailable", "An image is no longer available. Upload it again.", 422)


def check_images(conn, tenant, image_ids):
    """Read-only check that referenced uploads exist, for validation."""
    for image_id in image_ids:
        if not conn.execute(
            "SELECT 1 FROM dashboard_images WHERE tenant_id=%s AND id=%s", (tenant, image_id)
        ).fetchone():
            raise AppError("image_unavailable", "An image is no longer available. Upload it again.", 422)


def mark_used(conn, tenant, image_ids, now):
    if image_ids:
        conn.execute(
            "UPDATE dashboard_images SET first_used_at=%s WHERE tenant_id=%s AND id=ANY(%s) AND first_used_at IS NULL",
            (now, tenant, list(image_ids)),
        )
