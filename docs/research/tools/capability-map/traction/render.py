#!/usr/bin/env python3
"""Render the traction charts as self-contained SVGs from data.json.

    python3 render.py            # writes npm-downloads.svg, commit-activity.svg, github-stars.svg here

Colours are the validated reference palette (dataviz skill, light and dark, adjacent-pair checks pass).
Three light-mode slots sit below 3:1 contrast, so every series is direct-labelled and the numbers are
also in the table in ../PROTOCOLS.md.
"""
import json, math, html, datetime as dt, os

HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, 'data.json')))

SLOTS_L = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948']
SLOTS_D = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767']
FONT = "Helvetica, Arial, 'DejaVu Sans', sans-serif"


def css(extra=''):
    sl = ''.join(f'--s{i+1}:{c};' for i, c in enumerate(SLOTS_L))
    sd = ''.join(f'--s{i+1}:{c};' for i, c in enumerate(SLOTS_D))
    return f'''<style>
:root{{--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--ink3:#76756f;--grid:#e6e5e1;--axis:#b9b8b2;{sl}}}
@media (prefers-color-scheme:dark){{:root{{--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--ink3:#9a998f;--grid:#2c2c2a;--axis:#4a4a46;{sd}}}}}
text{{font-family:{FONT};fill:var(--ink2)}}
.t{{font-size:18px;font-weight:700;fill:var(--ink)}}
.sub{{font-size:12px;fill:var(--ink2)}}
.ax{{font-size:11px;fill:var(--ink3)}}
.lab{{font-size:12px;fill:var(--ink)}}
.val{{font-size:11px;fill:var(--ink2)}}
.grid{{stroke:var(--grid);stroke-width:1}}
.axis{{stroke:var(--axis);stroke-width:1}}
.ln{{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}}
.nd{{fill:none;stroke:var(--axis);stroke-width:1.5;stroke-dasharray:5 4}}
.ndt{{font-size:11px;font-style:italic;fill:var(--ink3)}}
.hit{{fill:transparent}}
.hit:hover{{fill:var(--ink);fill-opacity:.15}}
{extra}</style>'''


# Protocols with no series in a chart, and why. Shown as dashed "no data" markers rather than silently omitted.
NOT_PUBLIC = 'Closed commercial product: no public repository or package'
NO_NPM = [
    ('Baselayer KYA', NOT_PUBLIC),
    ('AP2', 'Not collected: no official npm package identified'),
    ('ACP', 'Not collected: no official npm package identified'),
    ('TAP', 'Not collected: no official npm package identified'),
    ('L402', 'Not collected: no official npm package identified'),
    ('ANS', 'Not collected: no official npm package identified'),
    ('PAP (Poppy)', 'Not collected: no package identified (spec and site only)'),
    ('KYAPay', 'Not collected: package not identified'),
    ('cheqd', 'Data exists (1.2K a week) but not plotted: the palette allows eight series'),
]


# Charted repository is an SDK or implementation, not the protocol's specification repository.
PROXY = {
    'MPP': 'wevm/mppx, the TypeScript SDK. The specification repository, tempoxyz/mpp-specs, is not charted.',
    'L402': 'lightninglabs/aperture, a reference implementation. The specification repository, lightninglabs/L402, is not charted.',
    'ANS': 'agentnameservice/ans, a Go reference implementation whose operator is unconfirmed. The IETF draft has no repository.',
    'Web Bot Auth': 'cloudflare/web-bot-auth, Cloudflare\'s implementation. The IETF draft is not charted.',
    'cheqd': 'cheqd/did-resolver, one cheqd repository. The cheqd network and other repositories are not charted.',
}


def star(n):
    return n + ('*' if n in PROXY else '')


def foot(x, y, lines):
    return ''.join(f'<text class="ax" x="{x}" y="{y+i*14}">{esc(t)}</text>' for i, t in enumerate(lines))


def short(repo):
    return repo.split('/')[1]


def wrap(text, n=135, indent='   '):
    cur, out = '', []
    for w in text.split(', '):
        add = (', ' if cur else '') + w
        if cur and len(cur) + len(add) > n:
            out.append(cur + ',')
            cur = indent + w
        else:
            cur += add
    return out + [cur]


def others_lines(metric):
    out = []
    for proto, repos in D.get('others', {}).items():
        key = (lambda r: -r['stars']) if metric == 'stars' else (lambda r: -(r['commits52w'] or 0))
        parts = []
        for r in sorted(repos, key=key):
            v = r['stars'] if metric == 'stars' else r['commits52w']
            parts.append(f"{short(r['repo'])} {'n/a' if v is None else format(v, ',')}")
        out += wrap(f'{proto}: ' + ', '.join(parts))
    return out


def package_lines():
    by = {}
    for p in D.get('other_packages', []):
        by.setdefault(p['protocol'], []).append(f"{p['package']} ({p['registry']}) {fmt(p['monthly'])}")
    out = []
    for proto, items in by.items():
        out += wrap(f'{proto}: ' + ', '.join(items))
    return out


def nc_height(sections):
    return 34 + sum(15 + 14 * len(lines) + 10 for _, lines in sections) + 6


def nc_box(x, y, w, sections):
    out = [f'<rect class="nd" x="{x}" y="{y}" width="{w}" height="{nc_height(sections)}" rx="6"/>',
           f'<text class="lab" x="{x+12}" y="{y+20}" style="font-weight:700">Not covered by this chart</text>']
    yy = y + 44
    for heading, lines in sections:
        out.append(f'<text class="val" x="{x+12}" y="{yy}" style="font-weight:700;fill:var(--ink)">{esc(heading)}</text>')
        for i, t in enumerate(lines):
            lead = len(t) - len(t.lstrip(' '))
            out.append(f'<text class="ndt" x="{x+12}" y="{yy+15+i*14}" style="font-style:normal">{esc(chr(160)*lead + t.lstrip(" "))}</text>')
        yy += 15 + 14 * len(lines) + 10
    return ''.join(out)


def esc(s):
    return html.escape(str(s))


def fmt(n):
    if n >= 1e6:
        return f'{n/1e6:.1f}M'.replace('.0M', 'M')
    if n >= 1e3:
        return f'{n/1e3:.1f}K'.replace('.0K', 'K') if n < 1e4 else f'{n/1e3:.0f}K'
    return f'{n:.0f}'


def svg(w, h, body, title, desc):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-labelledby="t d"><title id="t">{esc(title)}</title><desc id="d">{esc(desc)}</desc>{css()}'
            f'<rect width="{w}" height="{h}" fill="var(--surface)"/>{body}</svg>')


def nudge(ys, gap):
    """Spread label y positions so neighbours are at least gap apart (ys sorted ascending)."""
    out = list(ys)
    for i in range(1, len(out)):
        if out[i] - out[i-1] < gap:
            out[i] = out[i-1] + gap
    # pull back up if we overflowed the bottom
    return out


# ---------------------------------------------------------------- chart 1: npm downloads over time
def chart_npm():
    names = ['MCP', 'A2A', 'x402', 'MPP', 'Web Bot Auth', 'UCP', 'KYA-OS', 'x401']
    W = 960
    L, R, T = 64, 190, 112
    ph = 436
    secs = [('Protocols with no download series', [f'{n}: {why}' for n, why in NO_NPM]),
            ('Other packages, with downloads in the last month', package_lines()),
            ('Not measured', ['Maven, NuGet, Go modules, crates.io, RubyGems and any other registry, and packages whose name I could not identify.'])]
    hbox = nc_height(secs)
    H = T + ph + 40 + hbox + 22 + 28 + 10 + 28 + 14
    pw = W - L - R
    d0 = dt.date(2025, 4, 21)
    d1 = dt.date(2026, 10, 5)
    span = (d1 - d0).days
    lo, hi = 1, 8  # log10 axis: 10 .. 100M

    def X(d):
        return L + pw * (d - d0).days / span

    def Y(v):
        return T + ph * (1 - (math.log10(v) - lo) / (hi - lo))

    b = []
    b.append(f'<text class="t" x="{L}" y="30">Weekly npm downloads of each protocol\'s main SDK</text>')
    b.append(f'<text class="sub" x="{L}" y="50">Log scale, 21 Apr 2025 to 5 Oct 2026. Each line starts at the first week with downloads. Downloads include CI and mirrors.</text>')
    # legend
    lx = L
    for i, n in enumerate(names):
        b.append(f'<line x1="{lx}" x2="{lx+16}" y1="76" y2="76" class="ln" style="stroke:var(--s{i+1})"/>'
                 f'<text class="val" x="{lx+21}" y="80">{esc(n)}</text>')
        lx += 21 + 6.6 * len(n) + 26
    for k in range(lo, hi + 1):
        y = Y(10 ** k)
        b.append(f'<line class="grid" x1="{L}" x2="{L+pw}" y1="{y:.1f}" y2="{y:.1f}"/>'
                 f'<text class="ax" x="{L-8}" y="{y+4:.1f}" text-anchor="end">{fmt(10**k)}</text>')
    b.append(f'<line class="axis" x1="{L}" x2="{L+pw}" y1="{T+ph}" y2="{T+ph}"/>')
    for ds in ['2025-07-01', '2025-10-01', '2026-01-01', '2026-04-01', '2026-07-01', '2026-10-01']:
        d = dt.date.fromisoformat(ds)
        x = X(d)
        b.append(f'<line class="axis" x1="{x:.1f}" x2="{x:.1f}" y1="{T+ph}" y2="{T+ph+4}"/>'
                 f'<text class="ax" x="{x:.1f}" y="{T+ph+18}" text-anchor="middle">{d.strftime("%b %Y")}</text>')
    ends = []
    for i, n in enumerate(names):
        wk = D['npm'][n]['weeks']
        pts = [(dt.date.fromisoformat(a), v) for a, v in wk if v > 0]
        path = 'M' + ' L'.join(f'{X(a):.1f},{Y(v):.1f}' for a, v in pts)
        b.append(f'<path class="ln" style="stroke:var(--s{i+1})" d="{path}"/>')
        for a, v in pts:
            b.append(f'<circle class="hit" cx="{X(a):.1f}" cy="{Y(v):.1f}" r="7"><title>{esc(n)}: {v:,} downloads, week of {a.isoformat()}</title></circle>')
        a, v = pts[-1]
        ends.append((Y(v), i, n, v, X(a)))
    ends.sort()
    ly = nudge([e[0] for e in ends], 15)
    for (y, i, n, v, x), y2 in zip(ends, ly):
        lxp = L + pw + 16
        b.append(f'<path d="M{x+3:.1f},{y:.1f} L{lxp-3},{y2:.1f}" style="stroke:var(--s{i+1});stroke-width:1;fill:none"/>'
                 f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" style="fill:var(--s{i+1});stroke:var(--surface);stroke-width:2"/>'
                 f'<text class="lab" x="{lxp}" y="{y2+4:.1f}">{esc(n)} <tspan class="val">{fmt(v)}</tspan></text>')
    ny = T + ph + 40
    b.append(nc_box(L, ny, pw + R - 24, secs))
    b.append(foot(L, ny + hbox + 22, ['One package per protocol is plotted. The window opens 21 Apr 2025, so earlier history for MCP, x402 and Web Bot Auth is not shown.',
                                       'Each line starts at the first week with downloads.']))
    half = len(names) // 2
    for k, grp in enumerate((names[:half], names[half:])):
        pkgs = '; '.join(f'{n}: {D["npm"][n]["pkg"]}' for n in grp)
        b.append(f'<text class="ax" x="{L}" y="{ny+hbox+22+38+k*14}">{"Packages: " if k == 0 else ""}{esc(pkgs)}</text>')
    return svg(W, H, ''.join(b), 'Weekly npm downloads of each protocol main SDK',
               'Line chart on a log scale. ' + '; '.join(f'{n} {fmt(D["npm"][n]["weeks"][-1][1])} a week' for n in names))


# ---------------------------------------------------------------- chart 2: weekly commits, small multiples
def chart_commits():
    items = sorted(D['commits'].items(), key=lambda kv: -sum(v for _, v in kv[1]))
    items.append(('Baselayer KYA', None))  # no public repository
    cols, pw, ph = 5, 160, 70
    gx, gy = 28, 46
    L, T = 40, 124
    rows = math.ceil(len(items) / cols)
    W = L * 2 + cols * pw + (cols - 1) * gx
    secs = [('Protocols with no panel', ['Baselayer KYA: closed commercial product, no public repository.']),
            ('Other repositories, with commits in the last 52 weeks', others_lines('commits')),
            ('Counting', ['Default branch only. Forks, other branches and private repositories are not counted.'])]
    hbox = nc_height(secs)
    H = T + rows * (ph + gy) + 14 + 14 * (len(PROXY) + 1) + 16 + hbox + 24
    ymax = max(v for _, wk in items if wk for _, v in wk)
    ymax = int(math.ceil(ymax / 10.0) * 10)
    b = [f'<text class="t" x="{L}" y="30">Weekly commits to each protocol\'s main repository</text>',
         f'<text class="sub" x="{L}" y="50">Last 52 weeks to mid-Oct 2026. Same scale in every panel (0 to {ymax}), sorted by total commits.</text>',
         f'<text class="sub" x="{L}" y="68">A flat line on the baseline means no commits. Dashed shading means the repository did not exist yet. * marks an SDK or implementation repository (see below).</text>']
    for k, (n, wk) in enumerate(items):
        c, r = k % cols, k // cols
        x0 = L + c * (pw + gx)
        y0 = T + r * (ph + gy)
        if wk is None:
            b.append(f'<text class="lab" x="{x0}" y="{y0-18}" style="font-weight:700">{esc(n)}</text>'
                     f'<rect class="nd" x="{x0}" y="{y0}" width="{pw}" height="{ph}" rx="4"/>'
                     f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2-3}" text-anchor="middle">No data</text>'
                     f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2+12}" text-anchor="middle">closed product, no public repo</text>')
            continue
        tot = sum(v for _, v in wk)
        created = dt.date.fromisoformat(D['repos'][n]['created'])
        cut = 0
        while cut < len(wk) and dt.datetime.utcfromtimestamp(wk[cut][0]).date() + dt.timedelta(days=7) <= created:
            cut += 1
        b.append(f'<text class="lab" x="{x0}" y="{y0-18}" style="font-weight:700">{esc(star(n))}</text>'
                 f'<text class="val" x="{x0+pw}" y="{y0-18}" text-anchor="end">{tot:,} commit{"" if tot == 1 else "s"}</text>')
        b.append(f'<line class="grid" x1="{x0}" x2="{x0+pw}" y1="{y0}" y2="{y0}"/>'
                 f'<line class="axis" x1="{x0}" x2="{x0+pw}" y1="{y0+ph}" y2="{y0+ph}"/>')
        if c == 0:
            b.append(f'<text class="ax" x="{x0-6}" y="{y0+4}" text-anchor="end">{ymax}</text>'
                     f'<text class="ax" x="{x0-6}" y="{y0+ph+4}" text-anchor="end">0</text>')
        n_w = len(wk)
        px = lambda i: x0 + pw * i / (n_w - 1)
        py = lambda v: y0 + ph * (1 - v / ymax)
        if cut > 0:
            xc = px(min(cut, n_w - 1))
            b.append(f'<rect class="nd" x="{x0}" y="{y0}" width="{xc-x0:.1f}" height="{ph}" rx="3"/>')
            if xc - x0 >= 56:
                b.append(f'<text class="ndt" x="{(x0+xc)/2:.1f}" y="{y0+ph/2+4:.1f}" text-anchor="middle">created {created.strftime("%b %Y")}</text>')
        live = list(enumerate(wk))[cut:]
        if len(live) > 1:
            path = 'M' + ' L'.join(f'{px(i):.1f},{py(v):.1f}' for i, (_, v) in live)
            area = path + f' L{px(live[-1][0]):.1f},{y0+ph} L{px(live[0][0]):.1f},{y0+ph} Z'
            b.append(f'<path d="{area}" style="fill:var(--s1);fill-opacity:.18"/>'
                     f'<path class="ln" style="stroke:var(--s1)" d="{path}"/>')
        for i, (ts, v) in enumerate(wk):
            day = dt.datetime.utcfromtimestamp(ts).date().isoformat()
            msg = f'{n}: repository not yet created (created {created.isoformat()})' if i < cut else f'{n}: {v} commits, week of {day}'
            b.append(f'<rect class="hit" x="{px(i)-pw/n_w/2:.1f}" y="{y0}" width="{pw/n_w:.1f}" height="{ph}"><title>{esc(msg)}</title></rect>')
    fy = T + rows * (ph + gy) + 14
    b.append(foot(L, fy, ['* Charted repository is an SDK or implementation, not the specification:'] +
                  [f'   {k}: {v}' for k, v in PROXY.items()]))
    b.append(nc_box(L, fy + 14 * (len(PROXY) + 1) + 16, W - 2 * L, secs))
    return svg(W, H, ''.join(b), 'Weekly commits to each protocol main repository',
               'Small multiples, one panel per repository, shared scale. ' + '; '.join(f'{n} {sum(v for _, v in wk)} commits' for n, wk in items if wk) + '; Baselayer KYA has no data (closed product)')


# ---------------------------------------------------------------- chart 3: stars snapshot dot plot
def chart_stars():
    items = sorted(D['repos'].items(), key=lambda kv: -kv[1]['stars'])
    items.append(('Baselayer KYA', None))  # no public repository
    quiet = {n for n, wk in D['commits'].items() if sum(v for _, v in wk[-13:]) == 0}
    W = 960
    L, R, T = 150, 250, 100
    rh = 28
    secs = [('Protocols with no data', ['Baselayer KYA: closed commercial product, no public repository.']),
            ('Other repositories, with stars', ['One repository is charted per protocol. The MCP Python and TypeScript SDKs hold more stars than the specification repository charted.'] + others_lines('stars'))]
    hbox = nc_height(secs)
    H = T + len(items) * rh + 40 + 14 * (len(PROXY) + 1) + 16 + hbox + 24
    pw = W - L - R
    lo, hi = 1, 5  # 10 .. 100K

    def X(v):
        return L + pw * (math.log10(v) - lo) / (hi - lo)
    b = [f'<text class="t" x="{L-110}" y="30">GitHub stars on each protocol\'s main repository</text>',
         f'<text class="sub" x="{L-110}" y="50">Log scale, 16 Oct 2026. Stars measure attention, not use. Star history over time was not available from the GitHub API here.</text>']
    b.append(f'<circle cx="{L-106}" cy="76" r="5" style="fill:var(--s1);stroke:var(--surface);stroke-width:2"/><text class="val" x="{L-96}" y="80">Commits in the last 13 weeks</text>'
             f'<circle cx="{L+110}" cy="76" r="5" style="fill:var(--surface);stroke:var(--s1);stroke-width:2"/><text class="val" x="{L+120}" y="80">No commits in the last 13 weeks</text>')
    for k in range(lo, hi + 1):
        x = X(10 ** k)
        b.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{T-6}" y2="{T+len(items)*rh}"/>'
                 f'<text class="ax" x="{x:.1f}" y="{T+len(items)*rh+16}" text-anchor="middle">{fmt(10**k)}</text>')
    for i, (n, r) in enumerate(items):
        y = T + i * rh + rh / 2
        if r is None:
            b.append(f'<text class="lab" x="{L-12}" y="{y+4:.1f}" text-anchor="end">{esc(n)}</text>'
                     f'<rect class="nd" x="{L+8}" y="{y-10:.1f}" width="{pw-16}" height="20" rx="4"/>'
                     f'<text class="ndt" x="{L+20}" y="{y+4:.1f}">No data: closed commercial product, no public repository</text>')
            continue
        hollow = n in quiet
        fill = 'var(--surface)' if hollow else 'var(--s1)'
        b.append(f'<text class="lab" x="{L-12}" y="{y+4:.1f}" text-anchor="end">{esc(star(n))}</text>'
                 f'<circle cx="{X(r["stars"]):.1f}" cy="{y:.1f}" r="6" style="fill:{fill};stroke:var(--s1);stroke-width:2">'
                 f'<title>{esc(n)} ({esc(r["repo"])}): {r["stars"]:,} stars, {r["forks"]:,} forks, created {r["created"]}, last push {r["pushed"]}</title></circle>'
                 f'<text class="val" x="{X(r["stars"])+12:.1f}" y="{y+4:.1f}">{r["stars"]:,}  ·  created {dt.date.fromisoformat(r["created"]).strftime("%b %Y")}</text>')
    b.append(foot(L-110, T + len(items) * rh + 40, ['* Charted repository is an SDK or implementation, not the specification:'] +
                  [f'   {k}: {v}' for k, v in PROXY.items()]))
    b.append(nc_box(L - 110, T + len(items) * rh + 40 + 14 * (len(PROXY) + 1) + 16, W - 2 * (L - 110), secs))
    return svg(W, H, ''.join(b), 'GitHub stars on each protocol main repository',
               'Dot plot on a log scale. ' + '; '.join(f'{n} {r["stars"]:,}' for n, r in items if r) + '; Baselayer KYA has no data (closed product)')


if __name__ == '__main__':
    for name, fn in [('npm-downloads.svg', chart_npm), ('commit-activity.svg', chart_commits), ('github-stars.svg', chart_stars)]:
        open(os.path.join(HERE, name), 'w').write(fn())
        print('wrote', name)
