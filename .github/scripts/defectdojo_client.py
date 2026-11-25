#!/usr/bin/env python3
"""Cliente minimo para la API v2 de DefectDojo, solo con biblioteca estandar.

Se usa desde el pipeline y desde los scripts de configuracion local. No
imprime ni registra la API key.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class DefectDojoError(RuntimeError):
    """Error de comunicacion o de validacion devuelto por DefectDojo."""


class DefectDojoClient:
    def __init__(self, url, api_key, timeout=120, retries=3):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries

    # ------------------------------------------------------------------ HTTP
    def _headers(self, extra=None):
        headers = {
            "Authorization": f"Token {self.api_key}",
            "Accept": "application/json",
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "pai4-devsecops-ci/1.0",
        }
        if extra:
            headers.update(extra)
        return headers

    def _open(self, method, path, body=None, headers=None):
        request = urllib.request.Request(
            f"{self.url}{path}", data=body, headers=self._headers(headers), method=method
        )
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as error:
                raw = error.read().decode("utf-8", errors="replace")
                if error.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    last_error = f"HTTP {error.code}: {raw[:300]}"
                    time.sleep(2 ** attempt)
                    continue
                raise DefectDojoError(
                    f"{method} {path} -> HTTP {error.code}: {raw[:1200]}"
                ) from error
            except urllib.error.URLError as error:
                last_error = str(error)
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise DefectDojoError(f"{method} {path} -> {error}") from error
        raise DefectDojoError(last_error or "error desconocido")

    # ------------------------------------------------------------------ API
    def get(self, path, params=None):
        if params:
            path = f"{path}?{urllib.parse.urlencode(params)}"
        return self._open("GET", path)

    def post(self, path, data):
        body = json.dumps(data).encode("utf-8")
        return self._open("POST", path, body, {"Content-Type": "application/json"})

    def import_scan(self, engagement_id, scan_type, file_path, **extra):
        """POST /api/v2/import-scan/ con multipart/form-data."""
        with open(file_path, "rb") as report:
            content = report.read()
        fields = {
            "engagement": engagement_id,
            "scan_type": scan_type,
            "active": True,
            "verified": False,
            "minimum_severity": "Info",
            "close_old_findings": True,
            "deduplication_on_engagement": True,
            "deduplication_execution_mode": "sync",
            "apply_tags_to_findings": True,
            "tags": "ci,devsecops",
        }
        fields.update({key: value for key, value in extra.items() if value is not None})
        body, content_type = self._multipart(fields, file_path, content)
        return self._open(
            "POST",
            "/api/v2/import-scan/",
            body,
            {"Content-Type": content_type},
        )

    @staticmethod
    def _multipart(fields, file_path, content):
        boundary = f"----pai4{uuid.uuid4().hex}"
        parts = []
        for name, value in fields.items():
            if isinstance(value, bool):
                value = "true" if value else "false"
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n".encode("utf-8")
            )
        filename = file_path.rsplit("/", 1)[-1]
        parts.append(
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'
            ).encode("utf-8")
        )
        parts.append(content)
        parts.append(b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("utf-8"))
        return b"".join(parts), f"multipart/form-data; boundary={boundary}"
