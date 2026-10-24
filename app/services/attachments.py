"""Attachment inspection: dangerous types, disguised files, archives, EICAR."""
import io
import os
import zipfile
from dataclasses import dataclass, field
from typing import List

DANGEROUS = {"exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
              "msi", "jar", "hta", "lnk", "reg", "cpl", "dll", "iso", "img", "apk", "sh", "appx"}
MACRO = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVES = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
DOCUMENT_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png", "gif", "ppt", "pptx", "csv"}
EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
KNOWN_BAD_HASHES = set()  # populate with SHA-256 digests from threat intel feeds


@dataclass
class AttachmentFinding:
    filename: str
    content_type: str
    size: int
    sha256: str
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    @property
    def flagged(self):
        return self.score >= 30

    def add(self, pts, why):
        self.score = min(100, self.score + pts)
        self.reasons.append(why)


def _ext(name: str) -> str:
    return os.path.splitext(name.lower())[1].lstrip(".")


def inspect_attachment(att) -> AttachmentFinding:
    f = AttachmentFinding(att.filename, att.content_type, att.size, att.sha256)
    name = att.filename.lower()
    ext = _ext(name)
    head = att.data[:8]

    if EICAR in att.data or att.sha256 in KNOWN_BAD_HASHES:
        f.add(100, "Matches known malware signature (EICAR test / threat-intel hash)")
    if ext in DANGEROUS:
        f.add(65, f"Executable / script file type .{ext}")
    if ext in MACRO:
        f.add(35, f"Macro-enabled Office document .{ext}")
    stem_ext = _ext(os.path.splitext(name)[0])
    if stem_ext in DOCUMENT_EXT and ext in DANGEROUS | MACRO | ARCHIVES:
        f.add(40, f"Double extension (.{stem_ext}.{ext}) disguises file type")
    if head[:2] == b"MZ" and ext not in ("exe", "dll", "scr", "com", "sys"):
        f.add(55, "Windows executable disguised under a different extension")
    if head[:4] == b"\x7fELF" and ext not in ("elf", "so", "bin", ""):
        f.add(45, "Linux executable disguised under a different extension")
    if ext == "pdf" and att.data and not att.data.lstrip().startswith(b"%PDF"):
        f.add(30, "File named .pdf is not a real PDF")
    if ext in ARCHIVES:
        f.add(8, "Archive attachment (contents may hide malware)")
    if ext == "zip" or head[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(att.data)) as z:
                infos = z.infolist()[:200]
                if any(i.flag_bits & 0x1 for i in infos):
                    f.add(25, "Password-protected archive (evades scanners)")
                bad = [i.filename for i in infos if _ext(i.filename) in DANGEROUS]
                if bad and ext in ARCHIVES:
                    f.add(55, f"Archive contains executable content: {bad[0]}")
        except Exception:
            pass
    return f


def inspect_all(attachments) -> List[AttachmentFinding]:
    return [inspect_attachment(a) for a in attachments]


def attachment_points(findings: List[AttachmentFinding]) -> int:
    if not findings:
        return 0
    top = max(f.score for f in findings)
    return min(100, top)
