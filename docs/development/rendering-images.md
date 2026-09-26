# Rendering the social preview

`docs/img/` holds two SVG masters and one raster rendered from them. Edit the
masters and never the PNG.

| Master | Output | Used for |
| --- | --- | --- |
| `social-preview.svg` | `social-preview.png` | GitHub's social preview slot |
| `favicon.svg` | none | the mark on its own: the shield every guard shares, with a droplet for the spill |

The raster comes from [resvg](https://github.com/linebender/resvg), a static
binary that needs no browser. It is a dev-time tool and nothing here ships it.

```sh
resvg --sans-serif-family 'Helvetica Neue' --monospace-family Menlo \
  docs/img/social-preview.svg docs/img/social-preview.png
```

The master names CSS system-font stacks, which are keywords rather than
families, so the two flags pass faces resvg can resolve. The committed PNG was
rendered by resvg 0.48.1, and re-rendering an unchanged master under another
version rewrites the file, so render only after editing the master.

## `self-scan` names the PNG

The hook skips a file with a NUL in its first 8 KiB and allows the call with a
notice, so nothing reads a PNG's bytes. `scripts/check-self-scan.py` therefore
lists each tracked binary in `UNREAD` with a reason, and fails on one that is
not listed. A rendered image earns its entry because every word in it is in the
SVG beside it, which the gate does scan. A new raster needs a new entry.

## Publishing

GitHub does not accept SVG for a social preview. Upload the PNG under
**Settings → General → Social preview**.

Keep text at 7.5:1 or better against `#0d1117`: the preview is read on dark
backgrounds at whatever brightness the reader has set.
