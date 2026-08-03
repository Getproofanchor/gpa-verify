\# gpa-verify 1.5.0



\*\*This is a security release. Upgrade if you verify file-hash certification

bundles.\*\*



\## What was wrong



GetProofAnchor evidence bundles come in two kinds. A \*web capture\* records

what a URL displayed; a \*file digest certification\* records that a specific

file with a specific SHA-256 was obtained at a specific time. Every version of

this verifier up to and including 1.4.0 was written for the first kind only.



On a file-digest bundle it never read `files\_manifest.json`, and never

re-hashed the file contents preserved under `files/`. Two tampered bundles

therefore verified successfully:



\- the certified SHA-256 in `files\_manifest.json` replaced with an arbitrary

&#x20; value;

\- the bytes of a retained file replaced entirely, leaving the certified digest

&#x20; in place.



`manifest.json` is an index generated when the archive is assembled, after the

qualified timestamp is issued — so it is not sealed, and recomputing it defeats

the integrity layer on its own.



\## What changed



Two new checks bring the count to 10.



`file\_digest` compares every certified digest and size against

`capture/capture\_meta.json` and `content.txt`. Both are bound into the eIDAS

payload, so they cannot be altered without invalidating the TSA signature.

Where contents were retained, the stored bytes are re-hashed against the

certified digest.



`anchor\_witness` walks the inclusion witness from the proof's own chain entry

to the head the OpenTimestamps anchor covers, allowing the Bitcoin anchor to be

linked to the proof entirely offline.



\## Impact on existing bundles



Bundles created before witness support have no `chain/anchor\_witness.jsonl`.

These are reported as a \*\*skip\*\*, not a failure — nothing about them is

inconsistent, and their qualified timestamp is unaffected; only the offline

Bitcoin linkage cannot be demonstrated.



If you verified a file-digest bundle with 1.4.0 or earlier, re-run it.



\## Upgrade



&#x20;   pip install --upgrade gpa-verify

