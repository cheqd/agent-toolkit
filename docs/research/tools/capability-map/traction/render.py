#!/usr/bin/env python3
"""Render the traction charts as self-contained SVGs from data.json.

    python3 render.py            # writes npm-downloads.svg, commit-activity.svg, github-stars.svg here

Colours are the validated reference palette (dataviz skill, light and dark, adjacent-pair checks pass).
Three light-mode slots sit below 3:1 contrast, so every series is direct-labelled and the numbers are
also in the table in ../PROTOCOLS.md.
"""
import json, math, html, datetime as dt, os

HERE = os.path.dirname(os.path.abspath(__file__))
import importlib.util as _u
_sp = _u.spec_from_file_location('fetch_cfg', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fetch.py'))
_fc = _u.module_from_spec(_sp); _sp.loader.exec_module(_fc)
PACKAGES_CFG = _fc.PACKAGES
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
# Protocols with no public repository or package, charted as dashed no-data entries.
NO_REPO = [('Baselayer KYA', 'Closed commercial product: no public repository or package', 'closed product, no public repo'),
           ('Stripe SPT', "Proprietary API: no public repository; delivered through Stripe's general SDKs", 'proprietary API, no public repo'),
           ('Amex Intent Intelligence', 'Proprietary framework, part of the ACE Developer Kit: no specification or public repository found', 'proprietary, no public repo')]
NO_REPO_LINES = [f'{n}: {why[0].lower() + why[1:]}.' for n, why, _ in NO_REPO]
NO_REPO_NAMES = ', '.join(n for n, _, _ in NO_REPO)
NO_REPO_SHORT = {n: s for n, _, s in NO_REPO}


# Charted repository is an SDK or implementation, not the protocol's specification repository.
PROXY = {
    'MPP': 'wevm/mppx, the TypeScript SDK. The specification repository, tempoxyz/mpp-specs, is not charted.',
    'L402': 'lightninglabs/aperture, a reference implementation. The specification repository, lightninglabs/L402, is not charted.',
    'ANS': 'agentnameservice/ans, a Go reference implementation whose operator is unconfirmed. The IETF draft has no repository.',
    'AGNTCY': 'agntcy/oasf, the schema framework. The directory, SLIM, identity and SDK repositories are added in the commits chart and listed in each box.',
    'ERC-8004': 'erc-8004/erc-8004-contracts, reference contracts. The specification is an EIP, which has no GitHub repository.',
    'Web Bot Auth': 'cloudflare/web-bot-auth, Cloudflare\'s implementation. The IETF draft is not charted.',
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


def repo_label(r, shared):
    return short(r['repo']) + ('\u2020' if r['scope'] == 'third-party' else '') + ('\u2021' if r['repo'] in shared else '')


def shared_repos():
    seen, dup = {}, set()
    for proto, repos in D.get('others', {}).items():
        for r in repos:
            if r['repo'] in seen and seen[r['repo']] != proto:
                dup.add(r['repo'])
            seen[r['repo']] = proto
    return dup


def others_lines(metric):
    out, shared = [], shared_repos()
    for proto, repos in D.get('others', {}).items():
        key = (lambda r: -r['stars']) if metric == 'stars' else (lambda r: -(r['commits52w'] or 0))
        parts = []
        for r in sorted(repos, key=key):
            v = r['stars'] if metric == 'stars' else r['commits52w']
            parts.append(f"{repo_label(r, shared)} {'n/a' if v is None else format(v, ',')}")
        out += wrap(f'{proto}: ' + ', '.join(parts))
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
def chart_npm(notes=True):
    names = ['MCP', 'A2A', 'x402', 'MPP', 'Web Bot Auth', 'UCP', 'KYA-OS', 'x401']
    W = 960
    L, R, T = 64, 190, 112
    ph = 436
    dl = D['downloads']['by_protocol']
    extra = []
    for p, groups in dl.items():
        if p in names:
            continue
        parts = []
        for grp, regs in groups.items():
            for reg, r in regs.items():
                pub = f", {r['publisher']}" if r.get('publisher') else ''
                parts.append(f"{r['package']} ({reg}, {grp}{pub}) {fmt(r['monthly'])} last 4 weeks")
        if parts:
            extra.append(f'{p}: ' + '; '.join(parts))
    secs = [('Protocols with downloads that are not plotted here', ['This chart plots official npm packages only, up to the palette limit of eight series. These are in the all-registries chart:'] + extra),
            ('Protocols with no npm package found', NO_REPO_LINES +
             [f'{p}: {why}.' for p, why in D['downloads']['no_package'].items()]),
            ('Not measured', ['Third-party packages and other registries (PyPI, crates.io) are in the all-registries chart. Maven, NuGet and Go modules are not measured.'])]
    hbox = nc_height(secs)
    H = T + ph + 40 + (hbox + 22 + 28 + 10 + 28 + 14 if notes else 20)
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
    b.append(f'<text class="t" x="{L}" y="30">Weekly npm downloads of each protocol\'s main official SDK</text>')
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
    if notes:
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


# ---------------------------------------------------------------- chart 2: weekly commits, official vs third-party
def commit_series():
    """protocol -> official and third-party weekly commits, each added across its repositories."""
    out = {}
    for name, wk in D['commits'].items():
        off = dict(wk)
        off_repos = [D['repos'][name]['repo']]
        tp, tp_repos, missing = {}, [], []
        created = [D['repos'][name]['created']]
        for r in D.get('others', {}).get(name, []):
            if not r.get('weeks'):
                missing.append(short(r['repo']))
                continue
            created.append(r['created'])
            target, names = (tp, tp_repos) if r['scope'] == 'third-party' else (off, off_repos)
            names.append(r['repo'])
            for ts, n in r['weeks']:
                target[ts] = target.get(ts, 0) + n
        weeks = sorted(off)
        out[name] = dict(weeks=weeks, off=[off[t] for t in weeks], tp=[tp.get(t, 0) for t in weeks] if tp_repos else None,
                         off_repos=off_repos, tp_repos=tp_repos, created=min(created), missing=missing)
    return out


def legend_row(x, y, items):
    out, lx = [], x
    for label, col in items:
        out.append(f'<line x1="{lx}" x2="{lx+18}" y1="{y}" y2="{y}" class="ln" style="stroke:var({col})"/>'
                   f'<text class="val" x="{lx+24}" y="{y+4}">{esc(label)}</text>')
        lx += 24 + 6.2 * len(label) + 26
    return ''.join(out)


def chart_commits(notes=True):
    series = commit_series()
    items = sorted(series.items(), key=lambda kv: -(sum(kv[1]['off']) + sum(kv[1]['tp'] or [])))
    items += [(n, None) for n, _, _ in NO_REPO]  # no public repository
    cols, pw, ph = 5, 160, 70
    gx, gy = 28, 56
    L, T = 40, 150
    rows = math.ceil(len(items) / cols)
    W = L * 2 + cols * pw + (cols - 1) * gx
    shared = shared_repos()
    def names_of(n, key):
        return [short(r) + ('\u2021' if r in shared else '') for r in series[n][key]]
    off_lines, tp_lines = [], []
    for n, sr in series.items():
        off_lines += wrap(f'{n}: ' + ', '.join(names_of(n, 'off_repos')))
        if sr['tp_repos']:
            tp_lines += wrap(f'{n}: ' + ', '.join(names_of(n, 'tp_repos')))
        else:
            tp_lines.append(f'{n}: none found')
    gaps = sorted({m for sr in series.values() for m in sr['missing']})
    topics = ', '.join(f'{p} {c:,}' for p, (t, c) in D.get('topics', {}).items())
    secs = [('Protocols with no panel', NO_REPO_LINES),
            ('Official repositories added together in each panel', off_lines),
            ('Third-party repositories added together (hand-picked examples; \u2021 = counted under more than one protocol)', tp_lines),
            ('How third-party repositories were chosen', [
                'Up to three per protocol that implement the protocol itself (SDK, server, library, plugin), highest stars first,',
                'after setting aside applications that merely use it and curated lists. This is a sample, not a census.',
                'GitHub repositories tagged with each protocol topic, applications included: ' + topics + '.']),
            ('Not added', ([f'{", ".join(gaps)}: GitHub returned no commit statistics for these.'] if gaps else []) +
             ['Default branch only. Forks, other branches and private repositories are not counted.'])]
    hbox = nc_height(secs)
    H = T + rows * (ph + gy) + 14 + (hbox + 24 if notes else 10)
    ymax = max(max(sr['off'] + (sr['tp'] or [0])) for _, sr in items if sr)
    ymax = int(math.ceil(ymax / 10.0) * 10)
    b = [f'<text class="t" x="{L}" y="30">Weekly commits to each protocol: official and third-party repositories</text>',
         f'<text class="sub" x="{L}" y="50">Last 52 weeks to mid-Oct 2026. Same scale in every panel (0 to {ymax}), sorted by total commits.</text>',
         f'<text class="sub" x="{L}" y="68">Each line adds commits across its repositories, which are listed below. Dashed shading means no repository existed yet.</text>',
         legend_row(L, 94, [('Official repositories', '--s1'), ('Third-party implementations (hand-picked examples)', '--s2')])]
    for k, (n, sr) in enumerate(items):
        c, r = k % cols, k // cols
        x0 = L + c * (pw + gx)
        y0 = T + r * (ph + gy)
        if sr is None:
            b.append(f'<text class="lab" x="{x0}" y="{y0-30}" style="font-weight:700">{esc(n)}</text>'
                     f'<rect class="nd" x="{x0}" y="{y0}" width="{pw}" height="{ph}" rx="4"/>'
                     f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2-3}" text-anchor="middle">No data</text>'
                     f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2+12}" text-anchor="middle">{esc(NO_REPO_SHORT.get(n, "no public repo"))}</text>')
            continue
        wk = sr['weeks']
        n_w = len(wk)
        toff, ttp = sum(sr['off']), sum(sr['tp'] or [])
        created = dt.date.fromisoformat(sr['created'])
        cut = 0
        while cut < n_w and dt.datetime.utcfromtimestamp(wk[cut]).date() + dt.timedelta(days=7) <= created:
            cut += 1
        right = f'{toff:,} official' + (f' · {ttp:,} third-party' if sr['tp'] is not None else '')
        b.append(f'<text class="lab" x="{x0}" y="{y0-30}" style="font-weight:700">{esc(n)}</text>'
                 f'<text class="val" x="{x0}" y="{y0-16}">{right}</text>')
        b.append(f'<line class="grid" x1="{x0}" x2="{x0+pw}" y1="{y0}" y2="{y0}"/>'
                 f'<line class="axis" x1="{x0}" x2="{x0+pw}" y1="{y0+ph}" y2="{y0+ph}"/>')
        if c == 0:
            b.append(f'<text class="ax" x="{x0-6}" y="{y0+4}" text-anchor="end">{ymax}</text>'
                     f'<text class="ax" x="{x0-6}" y="{y0+ph+4}" text-anchor="end">0</text>')
        px = lambda i: x0 + pw * i / (n_w - 1)
        py = lambda v: y0 + ph * (1 - v / ymax)
        if cut > 0:
            xc = px(min(cut, n_w - 1))
            b.append(f'<rect class="nd" x="{x0}" y="{y0}" width="{xc-x0:.1f}" height="{ph}" rx="3"/>')
            if xc - x0 >= 56:
                b.append(f'<text class="ndt" x="{(x0+xc)/2:.1f}" y="{y0+ph/2+4:.1f}" text-anchor="middle">created {created.strftime("%b %Y")}</text>')
        live = list(range(cut, n_w))
        if len(live) > 1:
            path = 'M' + ' L'.join(f'{px(i):.1f},{py(sr["off"][i]):.1f}' for i in live)
            b.append(f'<path d="{path} L{px(live[-1]):.1f},{y0+ph} L{px(live[0]):.1f},{y0+ph} Z" style="fill:var(--s1);fill-opacity:.18"/>'
                     f'<path class="ln" style="stroke:var(--s1)" d="{path}"/>')
            if sr['tp'] is not None:
                pt = 'M' + ' L'.join(f'{px(i):.1f},{py(sr["tp"][i]):.1f}' for i in live)
                b.append(f'<path class="ln" style="stroke:var(--s2)" d="{pt}"/>')
        for i, ts in enumerate(wk):
            day = dt.datetime.utcfromtimestamp(ts).date().isoformat()
            if i < cut:
                msg = f'{n}: no repository yet (earliest created {created.isoformat()})'
            else:
                msg = f'{n}: {sr["off"][i]} official' + (f', {sr["tp"][i]} third-party' if sr['tp'] is not None else '') + f' commits, week of {day}'
            b.append(f'<rect class="hit" x="{px(i)-pw/n_w/2:.1f}" y="{y0}" width="{pw/n_w:.1f}" height="{ph}"><title>{esc(msg)}</title></rect>')
    if notes:
        b.append(nc_box(L, T + rows * (ph + gy) + 14, W - 2 * L, secs))
    return svg(W, H, ''.join(b), 'Weekly commits to each protocol: official and third-party repositories',
               'Small multiples, one panel per protocol, shared scale, official and third-party lines. ' +
               '; '.join(f'{n} {sum(sr["off"])} official' + (f' and {sum(sr["tp"])} third-party' if sr['tp'] is not None else '') + ' commits' for n, sr in items if sr) +
               '; no data for ' + NO_REPO_NAMES)


# ---------------------------------------------------------------- chart 2b: weekly downloads, official vs third-party
def chart_downloads(notes=True):
    DL = D['downloads']
    starts = [dt.date.fromisoformat(x) for x in DL['week_starts']]
    n_w = len(starts)

    def total(regs):
        return [sum(r['weeks'][i] for r in regs.values()) for i in range(n_w)] if regs else None
    rows_ = []
    for p, groups in DL['by_protocol'].items():
        off, tp = total(groups.get('official')), total(groups.get('third-party'))
        if off or tp:
            rows_.append((p, groups, off, tp))
    rows_.sort(key=lambda r: -((r[2] or [0])[-1] + (r[3] or [0])[-1]))
    nodata = [(n, 'no public repo or package') for n, _, _ in NO_REPO] + [(p, 'no package found') for p in DL['no_package']]
    cols, pw, ph = 4, 200, 64
    gx, gy = 44, 78
    L, T = 58, 146
    n_panels = len(rows_) + len(nodata)
    nrows = math.ceil(n_panels / cols)
    W = L * 2 + cols * pw + (cols - 1) * gx

    def pkg_lines(group):
        out = []
        for p, groups, _, _ in rows_:
            regs = groups.get(group) or {}
            if regs:
                parts = [f"{r['package']} ({reg}{', ' + r['publisher'] if r.get('publisher') else ''})" for reg, r in regs.items()]
                out += wrap(f'{p}: ' + ', '.join(parts))
        return out or ['none']
    alts = []
    for p, groups in DL['by_protocol'].items():
        for grp, regs in groups.items():
            for reg, r in regs.items():
                others = [n for n in PACKAGES_CFG.get(p, {}).get(grp, {}).get(reg, []) if n != r['package']]
                if others:
                    alts += wrap(f'{p} ({grp}, {reg}): {", ".join(others)}')
    topics = ', '.join(f'{p} {c:,}' for p, (t, c) in D.get('topics', {}).items())
    secs = [('Protocols with no data', NO_REPO_LINES + [f'{p}: {why}.' for p, why in DL['no_package'].items()]),
            ('Official packages counted (per registry, the most downloaded)', pkg_lines('official')),
            ('Third-party packages counted (hand-picked examples; the publisher is named)', pkg_lines('third-party')),
            ('Other packages of the same registry and group, not added (a package and its dependencies would be counted twice)', alts),
            ('Not measured', ['Maven, NuGet, Go modules, RubyGems, container pulls, and copies installed without a registry. Third-party repositories are a sample, not a census',
                              '(GitHub repositories tagged with each protocol topic: ' + topics + ').',
                              'Each registry gives a different history, so every panel covers the same 12 weeks.'])]
    hbox = nc_height(secs)
    H = T + nrows * (ph + gy) + 14 + (hbox + 24 if notes else 10)
    first, last = starts[0], starts[-1] + dt.timedelta(days=6)
    ymax_all = None
    b = [f'<text class="t" x="{L}" y="30">Weekly package downloads for each protocol: official and third-party packages</text>',
         f'<text class="sub" x="{L}" y="50">{first.strftime("%-d %b")} to {last.strftime("%-d %b %Y")}, across npm, PyPI and crates.io. Each panel has its own scale, from 0 to its peak.</text>',
         f'<text class="sub" x="{L}" y="68">Per registry and group, the most downloaded package is counted. The text under each panel gives the latest week by registry. CI and mirrors are included.</text>',
         legend_row(L, 92, [('Official packages', '--s1'), ('Third-party packages (hand-picked examples)', '--s2')])]
    k = 0
    for p, groups, off, tp in rows_:
        c, r = k % cols, k // cols
        x0 = L + c * (pw + gx)
        y0 = T + r * (ph + gy)
        k += 1
        ymax = max(max(off or [0]), max(tp or [0])) or 1
        px = lambda i: x0 + pw * i / (n_w - 1)
        py = lambda v: y0 + ph * (1 - v / ymax)
        head = f'{fmt(off[-1])} official a week' if off else f'{fmt(tp[-1])} third-party a week'
        b.append(f'<text class="lab" x="{x0}" y="{y0-18}" style="font-weight:700">{esc(p)}</text>'
                 f'<text class="val" x="{x0+pw}" y="{y0-18}" text-anchor="end">{head}</text>'
                 f'<line class="grid" x1="{x0}" x2="{x0+pw}" y1="{y0}" y2="{y0}"/>'
                 f'<line class="axis" x1="{x0}" x2="{x0+pw}" y1="{y0+ph}" y2="{y0+ph}"/>'
                 f'<text class="ax" x="{x0-6}" y="{y0+4}" text-anchor="end">{fmt(ymax)}</text>'
                 f'<text class="ax" x="{x0-6}" y="{y0+ph+4}" text-anchor="end">0</text>')
        both = [a + b_ for a, b_ in zip(off or [0] * n_w, tp or [0] * n_w)]
        cut = 0
        while cut < n_w - 1 and both[cut] == 0:
            cut += 1
        if cut > 0:  # weeks before the first download: no package existed yet
            xc = px(cut)
            b.append(f'<rect class="nd" x="{x0}" y="{y0}" width="{xc-x0:.1f}" height="{ph}" rx="3"/>'
                     f'<text class="ndt" x="{(x0+xc)/2:.1f}" y="{y0+ph/2+4:.1f}" text-anchor="middle">not published yet</text>')
        live = list(range(cut, n_w))
        if off:
            path = 'M' + ' L'.join(f'{px(i):.1f},{py(off[i]):.1f}' for i in live)
            b.append(f'<path d="{path} L{px(live[-1]):.1f},{y0+ph} L{px(live[0]):.1f},{y0+ph} Z" style="fill:var(--s1);fill-opacity:.18"/>'
                     f'<path class="ln" style="stroke:var(--s1)" d="{path}"/>')
        if tp:
            pt = 'M' + ' L'.join(f'{px(i):.1f},{py(tp[i]):.1f}' for i in live)
            fill = '' if off else f'<path d="{pt} L{px(live[-1]):.1f},{y0+ph} L{px(live[0]):.1f},{y0+ph} Z" style="fill:var(--s2);fill-opacity:.18"/>'
            b.append(fill + f'<path class="ln" style="stroke:var(--s2)" d="{pt}"/>')
        for i in range(n_w):
            parts = [f"{grp} {reg} {r_['weeks'][i]:,}" for grp, regs in groups.items() for reg, r_ in regs.items()]
            b.append(f'<rect class="hit" x="{px(i)-pw/n_w/2:.1f}" y="{y0}" width="{pw/n_w:.1f}" height="{ph}"><title>{esc(p)}, week of {starts[i].isoformat()}: {esc("; ".join(parts))}</title></rect>')
        ly = y0 + ph + 16
        for grp, label in (('official', 'Official'), ('third-party', 'Third-party')):
            regs = groups.get(grp) or {}
            if regs:
                mix = ' · '.join(f"{reg} {fmt(r_['weeks'][-1])}" for reg, r_ in regs.items())
                b.append(f'<text class="ax" x="{x0}" y="{ly}">{label}: {esc(mix)}</text>')
                ly += 13
    for p, why in nodata:
        c, r = k % cols, k // cols
        x0 = L + c * (pw + gx)
        y0 = T + r * (ph + gy)
        k += 1
        b.append(f'<text class="lab" x="{x0}" y="{y0-18}" style="font-weight:700">{esc(p)}</text>'
                 f'<rect class="nd" x="{x0}" y="{y0}" width="{pw}" height="{ph}" rx="4"/>'
                 f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2-3}" text-anchor="middle">No data</text>'
                 f'<text class="ndt" x="{x0+pw/2}" y="{y0+ph/2+12}" text-anchor="middle">{esc(why)}</text>')
    if notes:
        b.append(nc_box(L, T + nrows * (ph + gy) + 14, W - 2 * L, secs))
    return svg(W, H, ''.join(b), 'Weekly package downloads for each protocol: official and third-party packages',
               'Small multiples, one panel per protocol. ' + '; '.join(
                   f'{p} {fmt((off or [0])[-1])} official and {fmt((tp or [0])[-1])} third-party in the latest week' for p, _, off, tp in rows_) +
               '; no data for ' + ', '.join(p for p, _ in nodata))


# ---------------------------------------------------------------- chart 3: stars snapshot dot plot
def chart_stars(notes=True):
    items = sorted(D['repos'].items(), key=lambda kv: -kv[1]['stars'])
    items += [(n, None) for n, _, _ in NO_REPO]  # no public repository
    quiet = {n for n, wk in D['commits'].items() if sum(v for _, v in wk[-13:]) == 0}
    W = 960
    L, R, T = 150, 250, 100
    rh = 28
    secs = [('Protocols with no data', NO_REPO_LINES),
            ('Other repositories, with stars (\u2020 = third-party, hand-picked examples; \u2021 = counted under more than one protocol)',
             ['One repository is charted per protocol, and others can be larger: FastMCP and the MCP Python and TypeScript SDKs hold more stars than the MCP specification repository.'] + others_lines('stars')),
            ('Repositories tagged with each protocol topic, applications included',
             wrap(', '.join(f'{p} {c:,}' for p, (t, c) in D.get('topics', {}).items())))]
    hbox = nc_height(secs)
    H = T + len(items) * rh + 40 + 14 * (len(PROXY) + 1) + 16 + (hbox + 24 if notes else 10)
    pw = W - L - R
    lo, hi = 0.7, 5  # 5 .. 100K

    def X(v):
        return L + pw * (math.log10(v) - lo) / (hi - lo)
    b = [f'<text class="t" x="{L-110}" y="30">GitHub stars on each protocol\'s main repository</text>',
         f'<text class="sub" x="{L-110}" y="50">Log scale, 16 Oct 2026. Stars measure attention, not use. Star history over time was not available from the GitHub API here.</text>']
    b.append(f'<circle cx="{L-106}" cy="76" r="5" style="fill:var(--s1);stroke:var(--surface);stroke-width:2"/><text class="val" x="{L-96}" y="80">Commits in the last 13 weeks</text>'
             f'<circle cx="{L+110}" cy="76" r="5" style="fill:var(--surface);stroke:var(--s1);stroke-width:2"/><text class="val" x="{L+120}" y="80">No commits in the last 13 weeks</text>')
    for k in range(1, hi + 1):
        x = X(10 ** k)
        b.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{T-6}" y2="{T+len(items)*rh}"/>'
                 f'<text class="ax" x="{x:.1f}" y="{T+len(items)*rh+16}" text-anchor="middle">{fmt(10**k)}</text>')
    for i, (n, r) in enumerate(items):
        y = T + i * rh + rh / 2
        if r is None:
            b.append(f'<text class="lab" x="{L-12}" y="{y+4:.1f}" text-anchor="end">{esc(n)}</text>'
                     f'<rect class="nd" x="{L+8}" y="{y-10:.1f}" width="{pw-16}" height="20" rx="4"/>'
                     f'<text class="ndt" x="{L+20}" y="{y+4:.1f}">No data: {esc(dict((a, b) for a, b, _ in NO_REPO).get(n, "no public repository"))}</text>')
            continue
        hollow = n in quiet
        fill = 'var(--surface)' if hollow else 'var(--s1)'
        b.append(f'<text class="lab" x="{L-12}" y="{y+4:.1f}" text-anchor="end">{esc(star(n))}</text>'
                 f'<circle cx="{X(r["stars"]):.1f}" cy="{y:.1f}" r="6" style="fill:{fill};stroke:var(--s1);stroke-width:2">'
                 f'<title>{esc(n)} ({esc(r["repo"])}): {r["stars"]:,} stars, {r["forks"]:,} forks, created {r["created"]}, last push {r["pushed"]}</title></circle>'
                 f'<text class="val" x="{X(r["stars"])+12:.1f}" y="{y+4:.1f}">{r["stars"]:,}  ·  created {dt.date.fromisoformat(r["created"]).strftime("%b %Y")}</text>')
    b.append(foot(L-110, T + len(items) * rh + 40, ['* Charted repository is an SDK or implementation, not the specification:'] +
                  [f'   {k}: {v}' for k, v in PROXY.items()]))
    if notes:
        b.append(nc_box(L - 110, T + len(items) * rh + 40 + 14 * (len(PROXY) + 1) + 16, W - 2 * (L - 110), secs))
    return svg(W, H, ''.join(b), 'GitHub stars on each protocol main repository',
               'Dot plot on a log scale. ' + '; '.join(f'{n} {r["stars"]:,}' for n, r in items if r) + '; no data for ' + NO_REPO_NAMES)


if __name__ == '__main__':
    for name, fn in [('npm-downloads.svg', chart_npm), ('downloads-all-registries.svg', chart_downloads), ('commit-activity.svg', chart_commits), ('github-stars.svg', chart_stars)]:
        open(os.path.join(HERE, name), 'w').write(fn())
        print('wrote', name)
        no_notes_name = name.replace('.svg', '-no-notes.svg')
        open(os.path.join(HERE, no_notes_name), 'w').write(fn(notes=False))
        print('wrote', no_notes_name)
