from io import BytesIO

from PIL import Image as PillowImage

from app.services import ReportService


def test_normalize_report_image_bytes_returns_reencoded_image() -> None:
    source = BytesIO()
    PillowImage.new("RGBA", (8, 8), color=(126, 224, 255, 255)).save(source, format="PNG")

    normalized = ReportService._normalize_report_image_bytes(source.getvalue())

    assert normalized is not None
    with PillowImage.open(BytesIO(normalized)) as image:
        assert image.size == (8, 8)


def test_normalize_report_image_bytes_skips_invalid_payload() -> None:
    normalized = ReportService._normalize_report_image_bytes(b"not-an-image")

    assert normalized is None
