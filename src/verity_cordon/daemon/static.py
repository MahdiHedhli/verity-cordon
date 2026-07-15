"""Same-origin static delivery for the local Memory Control Room."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, Response

_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)


def default_control_room_dist() -> Path:
    return Path(__file__).resolve().parents[3] / "apps" / "control-room" / "dist"


def _headers(*, immutable: bool = False) -> dict[str, str]:
    return {
        "Cache-Control": ("public, max-age=31536000, immutable" if immutable else "no-store"),
        "Content-Security-Policy": _CSP,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }


def install_control_room(app: FastAPI, dist_directory: Path) -> None:
    root = dist_directory.resolve()

    @app.get("/{requested_path:path}", include_in_schema=False, response_model=None)
    async def control_room(requested_path: str) -> Response:
        if requested_path == "api" or requested_path.startswith("api/"):
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "message": "The API route was not found."},
                headers=_headers(),
            )
        if not root.is_dir():
            return JSONResponse(
                status_code=503,
                content={
                    "error": "control_room_unavailable",
                    "message": "Build the local Control Room before serving it.",
                },
                headers=_headers(),
            )

        relative = requested_path or "index.html"
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "message": "The asset was not found."},
                headers=_headers(),
            )
        if candidate.is_file():
            return FileResponse(
                candidate,
                headers=_headers(immutable=relative.startswith("assets/")),
            )
        if Path(relative).suffix:
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "message": "The asset was not found."},
                headers=_headers(),
            )
        return FileResponse(root / "index.html", headers=_headers())
