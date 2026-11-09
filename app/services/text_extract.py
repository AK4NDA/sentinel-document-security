"""Text extraction for search indexing (spec 0008).

Produces the plaintext that gets AES-GCM sealed into
``document_versions.search_text``. Everything here is CPU bound and must be
called through ``asyncio.to_thread``.
"""

import asyncio
import io
import logging

from app.security import encryption

logger = logging.getLogger(__name__)

MAX_EXTRACT_BYTES = 2 * 1024 * 1024

EXTRACTABLE_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "text/plain",
        "text/markdown",
        "text/csv",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)

_TEXT_MIME_TYPES = frozenset({"text/plain", "text/markdown", "text/csv"})
_DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"


def _cap(text: str) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_EXTRACT_BYTES:
        return text
    return encoded[:MAX_EXTRACT_BYTES].decode("utf-8", errors="ignore")


def _join(parts) -> str:
    out: list[str] = []
    size = 0
    for part in parts:
        if part is None:
            continue
        out.append(part)
        size += len(part)
        if size >= MAX_EXTRACT_BYTES:
            break
    return _cap("\n".join(out))


def _extract_pdf(content: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(content))
    return _join(page.extract_text() or "" for page in reader.pages)


def _extract_docx(content: bytes) -> str:
    import docx

    document = docx.Document(io.BytesIO(content))
    parts = [p.text for p in document.paragraphs]
    for table in document.tables:
        for row in table.rows:
            parts.extend(cell.text for cell in row.cells)
    return _join(parts)


def _extract_xlsx(content: bytes) -> str:
    import openpyxl

    workbook = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    parts = []
    size = 0
    try:
        for sheet in workbook.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for value in row:
                    if value is None:
                        continue
                    part = str(value)
                    parts.append(part)
                    size += len(part)
                    if size >= MAX_EXTRACT_BYTES:
                        return _join(parts)
    finally:
        workbook.close()
    return _join(parts)


def _extract_pptx(content: bytes) -> str:
    from pptx import Presentation

    presentation = Presentation(io.BytesIO(content))
    parts = []
    for slide in presentation.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                parts.append(shape.text_frame.text)
            if shape.has_table:
                for row in shape.table.rows:
                    parts.extend(cell.text for cell in row.cells)
    return _join(parts)


def _extract_text_plain(content: bytes) -> str:
    return _cap(content.decode("utf-8", errors="replace"))


def extract_text(mime_type: str, content: bytes) -> str | None:
    """Return extracted plain text, or None when the type is not extractable."""
    if mime_type not in EXTRACTABLE_MIME_TYPES:
        return None
    try:
        if mime_type == "application/pdf":
            return _extract_pdf(content)
        if mime_type == _DOCX_MIME:
            return _extract_docx(content)
        if mime_type == _XLSX_MIME:
            return _extract_xlsx(content)
        if mime_type == _PPTX_MIME:
            return _extract_pptx(content)
        return _extract_text_plain(content)
    except Exception:
        logger.warning("text extraction failed", extra={"mime_type": mime_type})
        return None


async def extract_search_text(mime_type: str, content: bytes) -> bytes | None:
    """Extract and AES-GCM seal; returns ciphertext for search_text, or None."""
    text = await asyncio.to_thread(extract_text, mime_type, content)
    if not text:
        return None
    return await asyncio.to_thread(encryption.seal, text.encode("utf-8"))
