# Capability map generator

Generates the capability map in [`../../images/protocol-capability-map.png`](../../images/protocol-capability-map.png), used by [`protocol-stack-2026-10.md`](../../protocol-stack-2026-10.md).

The ratings live in the `ROWS` list in `generate.py`. Edit them, regenerate and re-render. Box colour (overlap, partial overlap, gap) is computed from the ratings.

## Toggle for including cheqd

The same data produces two versions:

| Version | Command | Image |
|---|---|---|
| With cheqd | `python3 generate.py out.html` | [`protocol-capability-map.png`](../../images/protocol-capability-map.png) |
| Without cheqd | `python3 generate.py out.html --no-cheqd` | [`protocol-capability-map-neutral.png`](../../images/protocol-capability-map-neutral.png) |

`--no-cheqd` removes the cheqd chips, drops the capabilities only cheqd covered, and omits the Trust anchor row. `--without PROTOCOL` and `--skip-row ROW` do the same for other protocols and rows.

## Run

```bash
python3 generate.py capability-map.html            # with cheqd
python3 generate.py capability-map.html --no-cheqd # without cheqd
```

The script needs only Python 3 and prints the count in each category.

## Render to PNG

Any headless Chromium works. For example, with Chrome on macOS:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless \
  --hide-scrollbars --force-device-scale-factor=2 --window-size=1610,830 \
  --screenshot=protocol-capability-map.png file://$PWD/capability-map.html
```

The window size fits the current content. Use a height of 700 instead of 830 for the `--no-cheqd` version, and change it if you add rows.

## Limits

The ratings are an assessment from public specifications and secondary sources, not a verified comparison.
