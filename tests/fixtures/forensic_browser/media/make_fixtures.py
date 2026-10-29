"""Regenerate the 'Video & audio' fixtures (Forensic Browser 1.6.0, media/NN/).

Not run by pytest. Needs a checkout of the Forensic Browser app (its
EvidenceBuilder, media jobs, local test media server and self-made test TSA),
plus yt-dlp and ffmpeg:

    PYTHONPATH=<app> python make_fixtures.py <app> <this directory>

  media-zip.zip               ZIP package: page + original MP4 + playback recording
  media-dual_pdf.pdf          sealed PDF; media too large for the (test) PDF limit,
  media-dual_pdf_media.zip    so they travel in this companion archive
  media-dual_pdf_bez-pecete.pdf  plain copy
The second media item comes from a page that was NOT captured as a page (its URL
is printed in the copy), the case gpa-verify 1.7.1 rejected.
"""
import shutil
import sys
import tempfile
from pathlib import Path

app, out = Path(sys.argv[1]), Path(sys.argv[2])
sys.path[:0] = [str(app), str(app / "tests")]
import test_media_capture as T  # noqa: E402

try:
    res, b = T.build("zip", ["progressive", "recording"], lang="en")
    shutil.copy(res["zip"], out / "media-zip.zip")
    res, b = T.build("dual_pdf", ["progressive", "split"], lang="cs", embed_max=100_000)
    sid = b.session.session_id
    shutil.copy(res["pdf"], out / "media-dual_pdf.pdf")
    shutil.copy(res["plain"][0], out / "media-dual_pdf_bez-pecete.pdf")
    shutil.copy(b.companion_paths[0], out / "media-dual_pdf_media.zip")
    for p in sorted(out.iterdir()):
        print(p.name, p.stat().st_size)
finally:
    T.SRV.close()
