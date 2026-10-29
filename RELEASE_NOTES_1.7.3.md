# gpa-verify 1.7.3 — clear answer for the companion media archive

Forensic Browser 1.6+ writes a companion archive `…_media.zip` next to a sealed
PDF when video or audio is too large to embed. The archive carries no seal —
the PDF seals the SHA-256 of every file in it.

## What changes for you

- `gpa-verify GetProofAnchor_sess-…_media.zip` no longer ends in a cryptic
  `FAILED manifest_load`. It reports **NOT VERIFIABLE BY ITSELF** (exit code 3)
  and prints the command to run:

      gpa-verify GetProofAnchor_sess-….pdf --media GetProofAnchor_sess-…_media.zip

- `gpa-verify …_media.zip --original GetProofAnchor_sess-….pdf` does the same
  verification as the command above. Passing the unsealed plain copy
  (`…_bez-pecete.pdf`) as `--original` fails with a clear `original_kind`
  message.

## Compatibility

No change for SaaS evidence, Forensic Browser ZIP/PDF packages, plain copies
or report PDFs.
