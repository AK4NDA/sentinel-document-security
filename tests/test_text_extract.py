"""Unit tests for text extraction and search text sealing (spec 0008, AC-9, AC-10)."""

import asyncio
import io

from app.security import encryption
from app.services import text_extract


def _minimal_pdf(text: str) -> bytes:
    content = f"BT /F1 24 Tf 100 700 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + obj + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objs) + 1))
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xref)
    )
    return out.getvalue()


def _docx_bytes(text: str) -> bytes:
    import docx

    document = docx.Document()
    document.add_paragraph(text)
    buf = io.BytesIO()
    document.save(buf)
    return buf.getvalue()


def _xlsx_bytes(text: str) -> bytes:
    import openpyxl

    workbook = openpyxl.Workbook()
    workbook.active["A1"] = text
    buf = io.BytesIO()
    workbook.save(buf)
    return buf.getvalue()


def _pptx_bytes(text: str) -> bytes:
    from pptx import Presentation
    from pptx.util import Inches

    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[5])
    box = slide.shapes.add_textbox(Inches(1), Inches(1), Inches(4), Inches(1))
    box.text_frame.text = text
    buf = io.BytesIO()
    presentation.save(buf)
    return buf.getvalue()


DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"


def test_plain_text_extracts_utf8_with_replacement():
    content = "héllo wörld".encode() + b"\xff\xfe binary junk"
    text = text_extract.extract_text("text/plain", content)
    assert "héllo wörld" in text
    assert "\ufffd" in text  # invalid bytes become U+FFFD, never raise


def test_text_mime_variants_all_extract():
    for mime in ("text/plain", "text/markdown", "text/csv"):
        assert "needle" in text_extract.extract_text(mime, b"a needle here")


def test_extracted_text_capped_at_2mb():
    content = b"x" * (text_extract.MAX_EXTRACT_BYTES + 1000)
    text = text_extract.extract_text("text/plain", content)
    assert len(text.encode("utf-8")) <= text_extract.MAX_EXTRACT_BYTES


def test_non_extractable_mime_returns_none():
    assert text_extract.extract_text("image/png", b"fake png") is None
    assert text_extract.extract_text("application/octet-stream", b"x") is None


def test_empty_extraction_returns_none_via_seal_path():
    assert text_extract.extract_text("text/plain", b"") == ""
    sealed = asyncio.run(text_extract.extract_search_text("text/plain", b""))
    assert sealed is None


def test_pdf_extracts_text():
    text = text_extract.extract_text("application/pdf", _minimal_pdf("zxqwpdfbody"))
    assert "zxqwpdfbody" in text


def test_docx_extracts_paragraph_text():
    text = text_extract.extract_text(DOCX_MIME, _docx_bytes("zxqwdocxbody"))
    assert "zxqwdocxbody" in text


def test_xlsx_extracts_cell_values():
    text = text_extract.extract_text(XLSX_MIME, _xlsx_bytes("zxqwxlsxbody"))
    assert "zxqwxlsxbody" in text


def test_pptx_extracts_shape_text():
    text = text_extract.extract_text(PPTX_MIME, _pptx_bytes("zxqwpptxbody"))
    assert "zxqwpptxbody" in text


def test_corrupt_files_return_none_not_raise():
    garbage = b"this is not a real office document"
    for mime, payload in [
        ("application/pdf", garbage),
        (DOCX_MIME, garbage),
        (XLSX_MIME, garbage),
        (PPTX_MIME, garbage),
    ]:
        assert text_extract.extract_text(mime, payload) is None, mime


def test_extract_search_text_returns_decryptable_ciphertext():
    sealed = asyncio.run(text_extract.extract_search_text("text/plain", b"searchable secret body"))
    assert sealed is not None
    # same AES-GCM blob format as stored files: nonce prefixed ciphertext
    plaintext = encryption.open_blob(sealed).decode("utf-8")
    assert "searchable secret body" in plaintext
    assert b"searchable secret body" not in sealed


def test_extract_search_text_none_for_non_extractable():
    sealed = asyncio.run(text_extract.extract_search_text("image/png", b"png bytes"))
    assert sealed is None
