"""Regenerate the 'Files and documents' fixtures (getproofanchor-files-1).

Not run by pytest. Needs a checkout of the Forensic Browser app (it uses the
app's FilesEvidenceBuilder and its self-made test TSA):

    PYTHONPATH=<app> python make_fixtures.py <app> <this directory>

The time-stamps come from a self-made test TSA, so tsa_trust_root (and
tsl_qualified) cannot pass; every other check must.
"""
import shutil
import sys
import tempfile
from pathlib import Path

app, out = Path(sys.argv[1]), Path(sys.argv[2])
sys.path[:0] = [str(app), str(app / "tests")]
import test_files_evidence as T  # noqa: E402
from _files_fixtures import make_docx, make_pdf, make_text  # noqa: E402
from PIL import Image  # noqa: E402

src = Path(tempfile.mkdtemp())
img = Image.new("RGB", (320, 240), (30, 110, 160))
ex = Image.Exif()
ex[0x010F], ex[0x0110] = "Canon", "Canon EOS R6"
ex.get_ifd(0x8769)[0x9003] = "2026:10:20 14:03:11"
ex.get_ifd(0x8825)[1] = "N"
img.save(src / "foto_provozovna.jpg", format="JPEG", quality=80, exif=ex)
ins = [make_pdf(src / "protokol-kontroly.pdf"), src / "foto_provozovna.jpg",
       make_docx(src / "smlouva.docx"), make_text(src / "zaznam.txt")]
for name, fmt, lang in (("files", "zip", "cs"), ("files", "dual_pdf", "en")):
    res, b = T.build(tempfile.mkdtemp(), fmt, ins, lang=lang)
    for v in res.values():
        for p in (v if isinstance(v, list) else [v]):
            dst = out / p.name.replace(b.session.session_id, f"{name}-{fmt}")
            shutil.copy(p, dst)
            print(dst.name, dst.stat().st_size)
