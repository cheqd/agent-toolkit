# Capability map generator

Generates the capability map in [`../../images/protocol-capability-map.png`](../../images/protocol-capability-map.png), used by [`protocol-stack-2026-10.md`](../../protocol-stack-2026-10.md).

The ratings live in the `ROWS` list in `generate.py`. Edit them, regenerate and re-render. Box colour (overlap, partial overlap, gap) is computed from the ratings.

## Run

```bash
python3 generate.py capability-map.html
```

The script needs only Python 3 and prints the count in each category.

## Render to PNG

Any headless Chromium works. For example, with Chrome on macOS:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless \
  --hide-scrollbars --force-device-scale-factor=2 --window-size=1610,830 \
  --screenshot=protocol-capability-map.png file://$PWD/capability-map.html
```

The window size fits the current content. Change the height if you add rows.

## Limits

The ratings are an assessment from public specifications and secondary sources, not a verified comparison.
