#!/usr/bin/env python3

import argparse
import html
import struct
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EMU_PER_PIXEL = 9525
DEFAULT_MAX_WIDTH_INCHES = 4.0
IMAGE_EXTENSIONS = {".png"}
PAGE_WIDTH_TWIPS = 12240
PAGE_MARGIN_TWIPS = 1440
TWIPS_TO_EMU = 635
CONTENT_WIDTH_EMU = (PAGE_WIDTH_TWIPS - 2 * PAGE_MARGIN_TWIPS) * TWIPS_TO_EMU
DEVICE_MAX_WIDTH_INCHES = {
    "nanox": 4.0,
    "nanosp": 4.0,
    "flex": 1.9,
    "stax": 1.8,
    "apex_p": 2.0,
}


@dataclass
class ImageEntry:
    group_name: str
    relative_name: str
    source_path: Path
    media_name: str
    width_px: int
    height_px: int
    rel_id: str
    doc_pr_id: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a .docx gallery from Nano X snapshot images."
    )
    parser.add_argument(
        "--source",
        default="tests/ragger/snapshots/nanox",
        help="Snapshot root directory. Default: %(default)s",
    )
    parser.add_argument(
        "--output",
        default="doc/nanox_snapshots.docx",
        help="Output .docx file. Default: %(default)s",
    )
    parser.add_argument(
        "--title",
        default="Nano X Snapshot Gallery",
        help="Document title. Default: %(default)s",
    )
    parser.add_argument(
        "--max-width-inches",
        type=float,
        default=None,
        help="Maximum rendered image width in inches. Default: auto by device",
    )
    return parser.parse_args()


def png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        header = handle.read(24)
    if len(header) < 24 or header[:8] != PNG_SIGNATURE:
        raise ValueError(f"Unsupported PNG file: {path}")
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def iter_group_directories(root: Path) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir())


def collect_images(root: Path) -> list[ImageEntry]:
    if not root.is_dir():
        raise FileNotFoundError(f"Snapshot directory does not exist: {root}")

    entries: list[ImageEntry] = []
    media_index = 1
    doc_pr_id = 1
    rel_id = 1

    for group_dir in iter_group_directories(root):
        image_paths = sorted(
            path
            for path in group_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
        )
        for image_path in image_paths:
            width_px, height_px = png_dimensions(image_path)
            entries.append(
                ImageEntry(
                    group_name=group_dir.name,
                    relative_name=image_path.relative_to(group_dir).as_posix(),
                    source_path=image_path,
                    media_name=f"image{media_index:04d}{image_path.suffix.lower()}",
                    width_px=width_px,
                    height_px=height_px,
                    rel_id=f"rId{rel_id}",
                    doc_pr_id=doc_pr_id,
                )
            )
            media_index += 1
            doc_pr_id += 1
            rel_id += 1

    if not entries:
        raise ValueError(f"No PNG images found under: {root}")
    return entries


def resolve_max_width_inches(root: Path, requested_width: float | None) -> float:
    if requested_width is not None:
        return requested_width
    return DEVICE_MAX_WIDTH_INCHES.get(root.name, DEFAULT_MAX_WIDTH_INCHES)


def xml_escape(text: str) -> str:
    return html.escape(text, quote=True)


def paragraph_text(text: str, *, bold: bool = False, size: int | None = None) -> str:
    run_properties = []
    if bold:
        run_properties.append("<w:b/>")
    if size is not None:
        run_properties.append(f'<w:sz w:val="{size}"/>')
        run_properties.append(f'<w:szCs w:val="{size}"/>')
    props = f"<w:rPr>{''.join(run_properties)}</w:rPr>" if run_properties else ""
    return (
        "<w:p>"
        "<w:r>"
        f"{props}"
        f"<w:t xml:space=\"preserve\">{xml_escape(text)}</w:t>"
        "</w:r>"
        "</w:p>"
    )


def paragraph_page_break() -> str:
    return "<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>"


def image_size_emu(width_px: int, height_px: int, max_width_inches: float) -> tuple[int, int]:
    max_width_emu = int(max_width_inches * 914400)
    width_emu = width_px * EMU_PER_PIXEL
    height_emu = height_px * EMU_PER_PIXEL

    if width_emu <= max_width_emu:
        return width_emu, height_emu

    scale = max_width_emu / width_emu
    return max_width_emu, int(height_emu * scale)


def image_drawing_run(entry: ImageEntry, width_emu: int, height_emu: int) -> str:
    return f"""
<w:r>
  <w:drawing>
    <wp:inline distT="0" distB="0" distL="0" distR="0">
      <wp:extent cx="{width_emu}" cy="{height_emu}"/>
      <wp:docPr id="{entry.doc_pr_id}" name="{xml_escape(entry.relative_name)}"/>
      <a:graphic>
        <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
          <pic:pic>
            <pic:nvPicPr>
              <pic:cNvPr id="{entry.doc_pr_id}" name="{xml_escape(entry.media_name)}"/>
              <pic:cNvPicPr/>
            </pic:nvPicPr>
            <pic:blipFill>
              <a:blip r:embed="{entry.rel_id}"/>
              <a:stretch><a:fillRect/></a:stretch>
            </pic:blipFill>
            <pic:spPr>
              <a:xfrm>
                <a:off x="0" y="0"/>
                <a:ext cx="{width_emu}" cy="{height_emu}"/>
              </a:xfrm>
              <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
            </pic:spPr>
          </pic:pic>
        </a:graphicData>
      </a:graphic>
    </wp:inline>
  </w:drawing>
</w:r>
""".strip()


def layout_group_rows(
    group_images: list[ImageEntry], max_width_inches: float
) -> list[list[tuple[ImageEntry, int, int]]]:
    rows: list[list[tuple[ImageEntry, int, int]]] = []
    current_row: list[tuple[ImageEntry, int, int]] = []
    current_width = 0

    for entry in group_images:
        width_emu, height_emu = image_size_emu(
            entry.width_px, entry.height_px, max_width_inches
        )
        if current_row and current_width + width_emu > CONTENT_WIDTH_EMU:
            rows.append(current_row)
            current_row = []
            current_width = 0

        current_row.append((entry, width_emu, height_emu))
        current_width += width_emu

    if current_row:
        rows.append(current_row)

    return rows


def paragraph_image_row(row: list[tuple[ImageEntry, int, int]]) -> str:
    runs = "".join(
        image_drawing_run(entry, width_emu, height_emu)
        for entry, width_emu, height_emu in row
    )
    return f"<w:p>{runs}</w:p>"


def parent_label(entry: ImageEntry) -> str:
    parent = Path(entry.relative_name).parent
    if str(parent) == ".":
        return entry.group_name
    return parent.name


def build_document_xml(
    title: str, source_label: str, images: list[ImageEntry], max_width_inches: float
) -> str:
    body: list[str] = [
        paragraph_text(title, bold=True, size=32),
        paragraph_text(f"Source: {source_label}", bold=False, size=20),
        paragraph_text(
            "Images are grouped by top-level folder name and ordered lexicographically.",
            size=20,
        ),
    ]

    group_images: dict[str, list[ImageEntry]] = {}
    for entry in images:
        group_images.setdefault(entry.group_name, []).append(entry)

    for index, (group_name, entries) in enumerate(group_images.items()):
        if index > 0:
            body.append(paragraph_page_break())
        body.append(paragraph_text(group_name, bold=True, size=28))
        body.append(paragraph_text(f"{len(entries)} image(s)", size=20))

        folder_images: dict[str, list[ImageEntry]] = {}
        for entry in entries:
            folder_images.setdefault(parent_label(entry), []).append(entry)

        for folder_name, folder_entries in folder_images.items():
            body.append(paragraph_text(folder_name, bold=True, size=22))
            for row in layout_group_rows(folder_entries, max_width_inches):
                body.append(paragraph_image_row(row))

    body.append(
        "<w:sectPr>"
        "<w:pgSz w:w=\"12240\" w:h=\"15840\"/>"
        "<w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\" "
        "w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/>"
        "</w:sectPr>"
    )

    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<w:document "
        "xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" "
        "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" "
        "xmlns:o=\"urn:schemas-microsoft-com:office:office\" "
        "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" "
        "xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" "
        "xmlns:v=\"urn:schemas-microsoft-com:vml\" "
        "xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" "
        "xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" "
        "xmlns:w10=\"urn:schemas-microsoft-com:office:word\" "
        "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" "
        "xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" "
        "xmlns:w15=\"http://schemas.microsoft.com/office/word/2012/wordml\" "
        "xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\" "
        "xmlns:wpi=\"http://schemas.microsoft.com/office/word/2010/wordprocessingInk\" "
        "xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" "
        "xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" "
        "xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" "
        "xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\" "
        "mc:Ignorable=\"w14 wp14\">"
        "<w:body>"
        f"{''.join(body)}"
        "</w:body>"
        "</w:document>"
    )


def build_document_rels(images: list[ImageEntry]) -> str:
    rels = [
        (
            f'<Relationship Id="{entry.rel_id}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="media/{entry.media_name}"/>'
        )
        for entry in images
    ]
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        f"{''.join(rels)}"
        "</Relationships>"
    )


def build_root_rels() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" "
        "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" "
        "Target=\"word/document.xml\"/>"
        "<Relationship Id=\"rId2\" "
        "Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" "
        "Target=\"docProps/core.xml\"/>"
        "<Relationship Id=\"rId3\" "
        "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties\" "
        "Target=\"docProps/app.xml\"/>"
        "</Relationships>"
    )


def build_content_types() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        "<Default Extension=\"png\" ContentType=\"image/png\"/>"
        "<Override PartName=\"/word/document.xml\" "
        "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
        "<Override PartName=\"/docProps/core.xml\" "
        "ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>"
        "<Override PartName=\"/docProps/app.xml\" "
        "ContentType=\"application/vnd.openxmlformats-officedocument.extended-properties+xml\"/>"
        "</Types>"
    )


def build_core_props(title: str) -> str:
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<cp:coreProperties "
        "xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
        "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
        "xmlns:dcterms=\"http://purl.org/dc/terms/\" "
        "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        f"<dc:title>{xml_escape(title)}</dc:title>"
        "<dc:creator>Codex</dc:creator>"
        "<cp:lastModifiedBy>Codex</cp:lastModifiedBy>"
        f"<dcterms:created xsi:type=\"dcterms:W3CDTF\">{created}</dcterms:created>"
        f"<dcterms:modified xsi:type=\"dcterms:W3CDTF\">{created}</dcterms:modified>"
        "</cp:coreProperties>"
    )


def build_app_props() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Properties "
        "xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" "
        "xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">"
        "<Application>Microsoft Office Word</Application>"
        "</Properties>"
    )


def write_docx(
    output_path: Path,
    title: str,
    source_label: str,
    images: list[ImageEntry],
    max_width_inches: float,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", build_content_types())
        docx.writestr("_rels/.rels", build_root_rels())
        docx.writestr("docProps/core.xml", build_core_props(title))
        docx.writestr("docProps/app.xml", build_app_props())
        docx.writestr(
            "word/document.xml",
            build_document_xml(title, source_label, images, max_width_inches),
        )
        docx.writestr("word/_rels/document.xml.rels", build_document_rels(images))

        for entry in images:
            docx.write(entry.source_path, arcname=f"word/media/{entry.media_name}")


def main() -> None:
    args = parse_args()
    source = Path(args.source)
    output = Path(args.output)
    max_width_inches = resolve_max_width_inches(source, args.max_width_inches)

    images = collect_images(source)
    write_docx(output, args.title, str(source), images, max_width_inches)
    print(
        f"Wrote {len(images)} image(s) to {output} "
        f"(max width: {max_width_inches:.2f}in)"
    )


if __name__ == "__main__":
    main()
