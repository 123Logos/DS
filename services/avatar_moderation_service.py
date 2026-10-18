from __future__ import annotations

import hashlib
import io
import json
import mimetypes
import secrets
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, UploadFile
from PIL import Image, ImageOps

from core.config import AVATAR_PENDING_DIR, AVATAR_UPLOAD_DIR, settings
from core.database import get_conn
from core.logging import get_logger
from services.wechat_api import media_check_async

logger = get_logger(__name__)

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_FILES = 3
TERMINAL_STATUSES = {"pass", "risky", "failed", "expired"}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _safe_path(path_value: str | None, root: Path) -> Path | None:
    if not path_value:
        return None
    path = Path(path_value).resolve()
    root = root.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path


def _public_url(token: str) -> str:
    base = settings.public_base_url
    if not base:
        raise HTTPException(status_code=503, detail="HOST must be configured for WeChat media review")
    return f"{base}/wechat-wxa/media/avatar/{token}"


class AvatarModerationService:
    @staticmethod
    def _get_user_openid(user_id: int) -> str:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT openid FROM users WHERE id=%s AND status=0 LIMIT 1",
                    (user_id,),
                )
                row = cur.fetchone()
        if not row or not row.get("openid"):
            raise HTTPException(status_code=409, detail="WeChat mini program identity is not bound")
        return str(row["openid"])

    @staticmethod
    def _normalize_image(file: UploadFile, data: bytes, target: Path) -> None:
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only JPG, PNG, and WEBP images are supported")
        if len(data) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="Avatar must not exceed 2 MB")
        try:
            with Image.open(io.BytesIO(data)) as source:
                source.verify()
            with Image.open(io.BytesIO(data)) as source:
                image = ImageOps.exif_transpose(source).convert("RGB")
                image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                target.parent.mkdir(parents=True, exist_ok=True)
                image.save(target, format="JPEG", quality=85, optimize=True)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid image content") from exc

    @staticmethod
    def _cleanup_paths(paths: list[Path]) -> None:
        seen: set[Path] = set()
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Unable to remove avatar file: %s", path)

    @staticmethod
    def _avatar_paths(value: Any) -> list[Path]:
        if not value:
            return []
        try:
            urls = json.loads(value) if isinstance(value, str) else value
        except (TypeError, json.JSONDecodeError):
            urls = [value]
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list):
            return []
        paths: list[Path] = []
        for url in urls:
            if isinstance(url, str):
                candidate = AVATAR_UPLOAD_DIR / Path(url).name
                path = _safe_path(str(candidate), AVATAR_UPLOAD_DIR)
                if path:
                    paths.append(path)
        return paths

    @classmethod
    async def submit(cls, user_id: int, files: list[UploadFile]) -> dict[str, Any]:
        if not files:
            return cls.clear(user_id)
        if len(files) > MAX_FILES:
            raise HTTPException(status_code=400, detail="A maximum of 3 avatar files can be uploaded")
        if not settings.WECHAT_CONTENT_SECURITY_ENABLED:
            raise HTTPException(status_code=503, detail="Avatar content review is disabled")

        openid = cls._get_user_openid(user_id)
        batch_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
            minutes=settings.AVATAR_REVIEW_TTL_MINUTES
        )
        records: list[dict[str, Any]] = []
        created_files: list[Path] = []

        try:
            # Validate and normalize the complete batch before creating database rows.
            for file in files:
                data = await file.read()
                media_token = secrets.token_urlsafe(32)
                pending_path = (AVATAR_PENDING_DIR / f"avatar_pending_{user_id}_{uuid.uuid4().hex}.jpg").resolve()
                cls._normalize_image(file, data, pending_path)
                created_files.append(pending_path)
                records.append({"media_token": media_token, "pending_path": pending_path})

            with get_conn() as conn:
                with conn.cursor() as cur:
                    for record in records:
                        cur.execute(
                            """
                            INSERT INTO avatar_review_submissions
                                (batch_id, user_id, openid, media_token_hash,
                                 pending_file_path, status, expires_at, created_at)
                            VALUES (%s, %s, %s, %s, %s, 'pending', %s, NOW())
                            """,
                            (
                                batch_id,
                                user_id,
                                openid,
                                _token_hash(record["media_token"]),
                                str(record["pending_path"]),
                                expires_at,
                            ),
                        )
                        record["submission_id"] = int(cur.lastrowid)
                    conn.commit()
        except HTTPException:
            cls._cleanup_paths(created_files)
            raise
        except Exception as exc:
            cls._cleanup_paths(created_files)
            logger.error("Unable to create avatar review records: %s", exc, exc_info=True)
            raise HTTPException(status_code=502, detail="Avatar review is temporarily unavailable") from exc

        try:
            # Keep external calls outside the database transaction. A failed submission
            # invalidates the whole batch so that no unreviewed file remains accessible.
            for record in records:
                trace_id = await media_check_async(
                    media_url=_public_url(record["media_token"]),
                    openid=openid,
                    scene=settings.WECHAT_CONTENT_SECURITY_SCENE,
                )
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE avatar_review_submissions
                            SET trace_id=%s
                            WHERE id=%s AND status='pending'
                            """,
                            (trace_id, record["submission_id"]),
                        )
                        conn.commit()
        except HTTPException:
            cls._fail_batch(batch_id)
            raise
        except Exception as exc:
            cls._fail_batch(batch_id)
            logger.error("Unable to submit avatar review: %s", exc, exc_info=True)
            raise HTTPException(status_code=502, detail="Avatar review is temporarily unavailable") from exc

        return {
            "batch_id": batch_id,
            "status": "pending",
            "items": [
                {"submission_id": record["submission_id"], "status": "pending"}
                for record in records
            ],
            "message": "Avatar submitted for review",
        }

    @classmethod
    def _fail_batch(cls, batch_id: str) -> None:
        paths: list[Path] = []
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT pending_file_path
                        FROM avatar_review_submissions
                        WHERE batch_id=%s AND status IN ('pending', 'review')
                        """,
                        (batch_id,),
                    )
                    paths = [
                        path
                        for row in cur.fetchall()
                        if (path := _safe_path(row.get("pending_file_path"), AVATAR_PENDING_DIR))
                    ]
                    cur.execute(
                        """
                        UPDATE avatar_review_submissions
                        SET status='failed', reviewed_at=NOW()
                        WHERE batch_id=%s AND status IN ('pending', 'review')
                        """,
                        (batch_id,),
                    )
                    conn.commit()
        except Exception:
            logger.exception("Unable to mark avatar batch failed: %s", batch_id)
        cls._cleanup_paths(paths)

    @classmethod
    def clear(cls, user_id: int) -> dict[str, Any]:
        pending_files: list[Path] = []
        old_files: list[Path] = []
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT avatar_path FROM users WHERE id=%s FOR UPDATE", (user_id,))
                old = cur.fetchone()
                old_files = cls._avatar_paths(old.get("avatar_path") if old else None)
                cur.execute(
                    """
                    SELECT pending_file_path
                    FROM avatar_review_submissions
                    WHERE user_id=%s AND status IN ('pending', 'review')
                    """,
                    (user_id,),
                )
                pending_files = [
                    path
                    for row in cur.fetchall()
                    if (path := _safe_path(row.get("pending_file_path"), AVATAR_PENDING_DIR))
                ]
                cur.execute("UPDATE users SET avatar_path=NULL, updated_at=NOW() WHERE id=%s", (user_id,))
                cur.execute(
                    """
                    UPDATE avatar_review_submissions
                    SET status='expired', reviewed_at=NOW()
                    WHERE user_id=%s AND status IN ('pending', 'review')
                    """,
                    (user_id,),
                )
                conn.commit()
        cls._cleanup_paths(pending_files + old_files)
        return {"batch_id": None, "status": "cleared", "items": [], "message": "Avatar cleared"}

    @classmethod
    def get_media(cls, token: str) -> tuple[Path, str] | None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT pending_file_path, expires_at
                    FROM avatar_review_submissions
                    WHERE media_token_hash=%s AND status IN ('pending', 'review')
                    LIMIT 1
                    """,
                    (_token_hash(token),),
                )
                row = cur.fetchone()
        if not row or row["expires_at"] <= datetime.now(timezone.utc).replace(tzinfo=None):
            return None
        path = _safe_path(row["pending_file_path"], AVATAR_PENDING_DIR)
        if not path or not path.is_file():
            return None
        return path, mimetypes.guess_type(path.name)[0] or "image/jpeg"

    @classmethod
    def handle_result(cls, data: dict[str, Any]) -> None:
        trace_id = str(data.get("trace_id") or data.get("TraceId") or "")
        if not trace_id:
            logger.warning("Avatar review callback has no trace_id")
            return

        result = data.get("result") or data.get("Result") or {}
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                result = {}
        if not isinstance(result, dict):
            result = {}
        detail = data.get("detail") or data.get("Detail") or {}
        if not isinstance(detail, dict):
            detail = {}
        try:
            errcode = int(data.get("errcode") or result.get("errcode") or detail.get("errcode") or 0)
        except (TypeError, ValueError):
            errcode = -1
        suggest = str(result.get("suggest") or data.get("suggest") or "").lower()
        if errcode != 0:
            status = "failed"
        elif suggest in {"pass", "risky", "review"}:
            status = suggest
        else:
            logger.warning("Unknown avatar review callback result: trace_id=%s", trace_id)
            return

        old_files: list[Path] = []
        pending_files: list[Path] = []
        moved_files: list[tuple[Path, Path]] = []
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM avatar_review_submissions WHERE trace_id=%s FOR UPDATE", (trace_id,))
                    row = cur.fetchone()
                    if not row or row["status"] in TERMINAL_STATUSES:
                        return
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    if row["expires_at"] <= now:
                        expired_path = _safe_path(row.get("pending_file_path"), AVATAR_PENDING_DIR)
                        cur.execute(
                            "UPDATE avatar_review_submissions SET status='expired', reviewed_at=NOW() WHERE id=%s",
                            (row["id"],),
                        )
                        conn.commit()
                        if expired_path:
                            cls._cleanup_paths([expired_path])
                        return

                    label = result.get("label") or data.get("label")
                    cur.execute(
                        """
                        UPDATE avatar_review_submissions
                        SET status=%s, suggest=%s, label=%s, wechat_errcode=%s, reviewed_at=NOW()
                        WHERE id=%s
                        """,
                        (status, suggest or None, label, errcode, row["id"]),
                    )

                    if status in {"risky", "failed"}:
                        current_path = _safe_path(row.get("pending_file_path"), AVATAR_PENDING_DIR)
                        if current_path:
                            pending_files.append(current_path)
                        cur.execute(
                            """
                            SELECT pending_file_path
                            FROM avatar_review_submissions
                            WHERE batch_id=%s AND status IN ('pending', 'review')
                            """,
                            (row["batch_id"],),
                        )
                        pending_files = [
                            path
                            for item in cur.fetchall()
                            if (path := _safe_path(item.get("pending_file_path"), AVATAR_PENDING_DIR))
                        ] + pending_files
                        cur.execute(
                            """
                            UPDATE avatar_review_submissions
                            SET status=%s, reviewed_at=COALESCE(reviewed_at, NOW())
                            WHERE batch_id=%s AND status IN ('pending', 'review')
                            """,
                            (status, row["batch_id"]),
                        )
                    else:
                        cur.execute(
                            "SELECT * FROM avatar_review_submissions WHERE batch_id=%s FOR UPDATE",
                            (row["batch_id"],),
                        )
                        batch = cur.fetchall()
                        if all(item["status"] == "pass" for item in batch):
                            sources: list[Path] = []
                            for item in batch:
                                source = _safe_path(item["pending_file_path"], AVATAR_PENDING_DIR)
                                if not source or not source.is_file():
                                    raise RuntimeError("Pending avatar file is missing")
                                sources.append(source)

                            cur.execute("SELECT avatar_path FROM users WHERE id=%s FOR UPDATE", (row["user_id"],))
                            old_user = cur.fetchone()
                            old_files = cls._avatar_paths(old_user.get("avatar_path") if old_user else None)
                            urls: list[str] = []
                            for source in sources:
                                target = AVATAR_UPLOAD_DIR / source.name.replace("avatar_pending_", "avatar_", 1)
                                target.parent.mkdir(parents=True, exist_ok=True)
                                shutil.move(str(source), str(target))
                                moved_files.append((source, target))
                                urls.append(f"/pic/avatars/{target.name}")
                            cur.execute(
                                "UPDATE users SET avatar_path=%s, updated_at=NOW() WHERE id=%s",
                                (json.dumps(urls, ensure_ascii=False), row["user_id"]),
                            )
                    conn.commit()
        except Exception:
            for source, target in reversed(moved_files):
                try:
                    if target.exists() and not source.exists():
                        shutil.move(str(target), str(source))
                except OSError:
                    logger.exception("Unable to roll back avatar file move: %s", target)
            logger.exception("Unable to process avatar review callback: trace_id=%s", trace_id)
            return

        cls._cleanup_paths(pending_files + old_files)

    @classmethod
    def expire_stale(cls) -> int:
        """Mark expired pending reviews and remove their non-public files."""
        paths: list[Path] = []
        count = 0
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, pending_file_path
                        FROM avatar_review_submissions
                        WHERE status IN ('pending', 'review') AND expires_at <= NOW()
                        FOR UPDATE
                        """
                    )
                    rows = cur.fetchall()
                    paths = [
                        path
                        for row in rows
                        if (path := _safe_path(row.get("pending_file_path"), AVATAR_PENDING_DIR))
                    ]
                    if rows:
                        ids = [int(row["id"]) for row in rows]
                        placeholders = ",".join(["%s"] * len(ids))
                        cur.execute(
                            f"UPDATE avatar_review_submissions SET status='expired', reviewed_at=NOW() "
                            f"WHERE id IN ({placeholders})",
                            tuple(ids),
                        )
                    conn.commit()
                    count = len(rows)
        except Exception:
            logger.exception("Unable to clean expired avatar reviews")
            return 0
        cls._cleanup_paths(paths)
        return count

    @staticmethod
    def get_status(user_id: int, batch_id: str) -> dict[str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM avatar_review_submissions WHERE user_id=%s AND batch_id=%s ORDER BY id",
                    (user_id, batch_id),
                )
                rows = cur.fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="Avatar review record not found")
        statuses = {row["status"] for row in rows}
        if "risky" in statuses:
            overall = "risky"
        elif "failed" in statuses:
            overall = "failed"
        elif "expired" in statuses:
            overall = "expired"
        elif all(status == "pass" for status in statuses):
            overall = "pass"
        elif "review" in statuses:
            overall = "review"
        else:
            overall = "pending"
        return {
            "batch_id": batch_id,
            "status": overall,
            "items": [{"submission_id": row["id"], "status": row["status"]} for row in rows],
        }
