"""Module description: Ye file EML mail ko parse karke decoded attachments nikalti hai."""

from __future__ import annotations

import logging
import mimetypes
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from .config import MAX_ATTACHMENT_BYTES
from .models import ExtractedFile

LOGGER = logging.getLogger(__name__)


def parse_eml(eml_path: Path) -> Message:
    """Ye raw .eml file ko parse karke Python email message object return karta hai."""

    with eml_path.open("rb") as handle:
        return BytesParser(policy=policy.default).parse(handle)


def safe_attachment_name(part: Message, index: int) -> str:
    """Ye attachment ka safe filename banata hai, chahe mail me naam diya ho ya na ho."""

    filename = part.get_filename()
    if filename:
        return Path(filename).name
    extension = mimetypes.guess_extension(part.get_content_type()) or ".bin"
    return f"attachment_{index}{extension}"


def extract_attachments(message: Message, output_dir: Path) -> list[ExtractedFile]:
    """Ye parsed email se attachments nikal kar decode karta hai aur disk par save karta hai."""

    extracted: list[ExtractedFile] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # iter_attachments() sirf attachment parts ko iterate karta hai, body ko nahi.
    for index, part in enumerate(message.iter_attachments(), start=1):
        payload = part.get_payload(decode=True)
        if payload is None:
            LOGGER.warning("Skipping attachment %s because payload decoding returned no bytes.", index)
            continue
        if len(payload) > MAX_ATTACHMENT_BYTES:
            LOGGER.warning("Skipping attachment %s because it exceeds the configured size limit.", index)
            continue

        filename = safe_attachment_name(part, index)
        destination = output_dir / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

        # Har extracted file ko metadata ke saath track kiya jata hai taaki baad me scan/report me kaam aaye.
        extracted.append(
            ExtractedFile(
                path=destination,
                source_name=filename,
                media_type=part.get_content_type(),
                detected_type="unknown",
                depth=0,
            )
        )
        LOGGER.info("Extracted attachment %s to %s", filename, destination)

    return extracted
