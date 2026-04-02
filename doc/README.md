# Snapshot Docx Generation

Use generate_nanox_docx.py to build `.docx` galleries from ragger snapshot directories.

## Commands

`nanox`:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/nanox \
  --output doc/nanox_snapshots.docx \
  --title "Nano X Snapshot Gallery"
```

`nanosp`:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/nanosp \
  --output doc/nanosp_snapshots.docx \
  --title "Nano S Plus Snapshot Gallery"
```

`flex`:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/flex \
  --output doc/flex_snapshots.docx \
  --title "Flex Snapshot Gallery"
```

`stax`:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/stax \
  --output doc/stax_snapshots.docx \
  --title "Stax Snapshot Gallery"
```

`apex_p`:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/apex_p \
  --output doc/apex_p_snapshots.docx \
  --title "Apex P Snapshot Gallery"
```

## Notes

- The script embeds images directly into the `.docx` file.
- Folder names are shown in the document; `.png` filenames are not shown.
- `flex`, `stax`, and `apex_p` use tighter default image widths automatically.
- You can override the image width manually with `--max-width-inches`.

Example:

```bash
python3 doc/generate_nanox_docx.py \
  --source tests/ragger/snapshots/stax \
  --output doc/stax_snapshots.docx \
  --title "Stax Snapshot Gallery" \
  --max-width-inches 1.5
```
