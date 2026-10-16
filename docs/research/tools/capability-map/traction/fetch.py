#!/usr/bin/env python3
"""Collect traction data (GitHub repo stats, weekly commits, weekly npm downloads) into data.json.

    python3 fetch.py [out.json]

Needs the `gh` CLI, logged in. Takes a minute or two: GitHub computes commit statistics lazily.
"""
import datetime as dt, json, subprocess, sys, time, urllib.request

REPOS = {'A2A': 'a2aproject/A2A', 'MCP': 'modelcontextprotocol/modelcontextprotocol', 'x402': 'x402-foundation/x402',
         'UCP': 'Universal-Commerce-Protocol/ucp', 'AP2': 'google-agentic-commerce/AP2',
         'ACP': 'agentic-commerce-protocol/agentic-commerce-protocol', 'TAP': 'visa/trusted-agent-protocol',
         'MPP': 'wevm/mppx', 'L402': 'lightninglabs/aperture', 'Web Bot Auth': 'cloudflare/web-bot-auth',
         'ANS': 'agentnameservice/ans', 'x401': 'proof/x401', 'KYA-OS': 'decentralized-identity/kya-os-mcp',
         'PAP': 'personal-agent-protocol/personal-agent-protocol', 'KYAPay': 'skyfire-xyz/kyapay'}
NPM = {'MCP': '@modelcontextprotocol/sdk', 'A2A': '@a2a-js/sdk', 'x402': 'x402', 'MPP': 'mppx',
       'Web Bot Auth': 'web-bot-auth', 'UCP': '@ucp-js/sdk', 'KYA-OS': '@kya-os/mcp', 'x401': '@proof.com/x401-node'}


# Other repositories and packages for each protocol. They are not charted as series, but each chart lists them
# under "Not covered by this chart" so the single repository or package plotted is not mistaken for the whole ecosystem.
# 'first-party' repositories belong to the protocol's own organisation (or its named steward) and are added to the
# protocol's commit series. 'community' repositories are third-party implementations: listed, not aggregated.
FP, CM = 'first-party', 'community'
OTHERS = {
    'A2A': [('a2aproject/a2a-python', FP), ('a2aproject/a2a-js', FP), ('a2aproject/a2a-java', FP), ('a2aproject/a2a-go', FP),
            ('a2aproject/a2a-dotnet', FP), ('a2aproject/a2a-rs', FP), ('a2aproject/a2a-samples', FP), ('a2aproject/a2a-inspector', FP)],
    'MCP': [('modelcontextprotocol/typescript-sdk', FP), ('modelcontextprotocol/python-sdk', FP), ('modelcontextprotocol/java-sdk', FP),
            ('modelcontextprotocol/go-sdk', FP), ('modelcontextprotocol/csharp-sdk', FP), ('modelcontextprotocol/rust-sdk', FP)],
    'x402': [('x402-foundation/wg-identity', FP), ('google-agentic-commerce/a2a-x402', CM)],
    'UCP': [('Universal-Commerce-Protocol/python-sdk', FP), ('Universal-Commerce-Protocol/js-sdk', FP),
            ('Universal-Commerce-Protocol/samples', FP), ('Universal-Commerce-Protocol/conformance', FP),
            ('Universal-Commerce-Protocol/ucp-schema', FP)],
    'MPP': [('tempoxyz/mpp-specs', FP)],
    'L402': [('lightninglabs/L402', FP), ('lightninglabs/lightning-agent-tools', FP)],
    'ANS': [('agentnameservice/ans-registry', FP)],
    'PAP': [('datalayer/personal-agent-protocol', CM), ('richardanaya/pi-poppy', CM), ('akshay5995/poppyseed', CM)],
    'x401': [('proof/x401-node', FP), ('proof/x401-ruby', FP)],
    'KYAPay': [('skyfire-xyz/kyapay_a2a', FP)],
}
# Packages per protocol and registry. For each registry the package with the most downloads in the last four weeks
# is charted (so a package and its dependencies are not both counted), and registries are added together.
# Scope: first-party = the protocol's own organisation; vendor = built by a named partner for the protocol;
# community = third-party implementation.
PACKAGES = {
    'A2A': {'npm': ['@a2a-js/sdk'], 'pypi': ['a2a-sdk'], 'crates': ['a2a-lf', 'a2a-pb']},
    'MCP': {'npm': ['@modelcontextprotocol/sdk'], 'pypi': ['mcp'], 'crates': ['rmcp']},
    'x402': {'npm': ['x402', '@x402/core', '@x402/extensions', '@x402/fetch', '@x402/mcp'], 'pypi': ['x402']},
    'UCP': {'npm': ['@ucp-js/sdk'], 'pypi': ['ucp-sdk'], 'crates': ['ucp-schema']},
    'MPP': {'npm': ['mppx'], 'pypi': ['pympp', 'pytempo']},
    'Web Bot Auth': {'npm': ['web-bot-auth', 'http-message-sig', 'jsonwebkey-thumbprint'], 'crates': ['web-bot-auth']},
    'KYA-OS': {'npm': ['@kya-os/mcp', '@kya-os/mcp-i']},
    'x401': {'npm': ['@proof.com/x401-node']},
    'PAP': {'npm': ['@datalayer/personal-agent-protocol', 'poppyseed'], 'pypi': ['personal-agent-protocol']},
    'L402': {'npm': ['@lightninglabs/l402', '@lightninglabs/lightning-mcp-server'], 'pypi': ['l402']},
    'ACP': {'npm': ['agentic-commerce-protocol'], 'pypi': ['agentic-commerce-protocol']},
    'KYAPay': {'npm': ['@skyfire-xyz/skyfire-seller-sdk-node']},
}
PACKAGE_SCOPE = {'poppyseed': 'community', '@datalayer/personal-agent-protocol': 'community', 'personal-agent-protocol': 'community',
                 'l402': 'community', 'agentic-commerce-protocol': 'vendor (Svix)', '@skyfire-xyz/skyfire-seller-sdk-node': 'vendor (Skyfire)',
                 'pympp': 'first-party (Tempo)', 'pytempo': 'first-party (Tempo)', 'mppx': 'vendor (wevm)'}
# Protocols where no package was found on npm, PyPI or crates.io, with what was checked.
NO_PACKAGE = {'AP2': 'The ap2 package on PyPI belongs to an unrelated project; no official npm or crates.io package found',
              'TAP': 'No package found on npm, PyPI or crates.io',
              'ANS': 'No package found on npm, PyPI or crates.io (Go reference implementation)'}


def gh(path):
    r = subprocess.run(['gh', 'api', path], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None


def repos():
    out = {}
    for n, r in REPOS.items():
        j = gh(f'repos/{r}')
        out[n] = dict(repo=r, stars=j['stargazers_count'], forks=j['forks_count'],
                      created=j['created_at'][:10], pushed=j['pushed_at'][:10])
    return out


def commits():
    out = {}
    for n, r in REPOS.items():
        for _ in range(8):  # the stats endpoint returns {} until GitHub has computed it
            d = gh(f'repos/{r}/stats/commit_activity')
            if isinstance(d, list) and d:
                out[n] = [(w['week'], w['total']) for w in d]
                break
            time.sleep(3)
    return out


def others():
    out = {}
    for proto, repos in OTHERS.items():
        for r, scope in repos:
            j = gh(f'repos/{r}')
            if not j or 'stargazers_count' not in j:
                continue
            weeks = None
            for _ in range(6):
                d = gh(f'repos/{r}/stats/commit_activity')
                if isinstance(d, list) and d:
                    weeks = [(w['week'], w['total']) for w in d]
                    break
                time.sleep(3)
            out.setdefault(proto, []).append(dict(
                repo=r, scope=scope, stars=j['stargazers_count'], created=j['created_at'][:10], pushed=j['pushed_at'][:10],
                commits52w=sum(v for _, v in weeks) if weeks else None, weeks=weeks, archived=j['archived']))
    return out


def _week_starts(n=12):
    end = dt.date.today() - dt.timedelta(days=1)
    end -= dt.timedelta(days=(end.weekday() + 1) % 7)  # last Sunday on or before yesterday
    return [end - dt.timedelta(days=7 * i + 6) for i in range(n - 1, -1, -1)]


def _daily(registry, name):
    """Daily downloads for one package: {iso date: n}. npm 540 days, PyPI about 180, crates.io 90."""
    q = name.replace('/', '%2F')
    try:
        if registry == 'npm':
            end = dt.date.today() - dt.timedelta(days=1)
            u = f'https://api.npmjs.org/downloads/range/{end - dt.timedelta(days=120)}:{end}/{q}'
            return {x['day']: x['downloads'] for x in json.load(urllib.request.urlopen(u, timeout=30))['downloads']}
        if registry == 'pypi':
            time.sleep(1.5)  # pypistats rate-limits
            r = urllib.request.Request(f'https://pypistats.org/api/packages/{name}/overall?mirrors=false', headers={'User-Agent': 'traction-script'})
            d = json.load(urllib.request.urlopen(r, timeout=30))['data']
            return {x['date']: x['downloads'] for x in d if x['category'] == 'without_mirrors'}
        r = urllib.request.Request(f'https://crates.io/api/v1/crates/{name}/downloads', headers={'User-Agent': 'traction-script'})
        d = json.load(urllib.request.urlopen(r, timeout=30))
        days = {}
        for x in d['version_downloads'] + d['meta']['extra_downloads']:
            days[x['date']] = days.get(x['date'], 0) + x['downloads']
        return days
    except Exception:
        return None


def downloads():
    starts = _week_starts()
    out = {}
    for proto, regs in PACKAGES.items():
        out[proto] = {}
        for registry, names in regs.items():
            best = None
            for name in names:
                days = _daily(registry, name)
                if not days:
                    continue
                weeks = [sum(days.get((w + dt.timedelta(days=i)).isoformat(), 0) for i in range(7)) for w in starts]
                if best is None or sum(weeks[-4:]) > sum(best['weeks'][-4:]):
                    best = dict(package=name, weeks=weeks, scope=PACKAGE_SCOPE.get(name, 'first-party'),
                                candidates=len(names))
            if best:
                best['monthly'] = sum(best['weeks'][-4:])
                out[proto][registry] = best
    return dict(week_starts=[w.isoformat() for w in starts], by_protocol=out, no_package=NO_PACKAGE)


def npm():
    end = dt.date.today() - dt.timedelta(days=1)
    start = end - dt.timedelta(days=540)
    out = {}
    for n, p in NPM.items():
        u = f"https://api.npmjs.org/downloads/range/{start}:{end}/{p.replace('/', '%2F')}"
        days = {x['day']: x['downloads'] for x in json.load(urllib.request.urlopen(u, timeout=30))['downloads']}
        cur = start + dt.timedelta(days=(7 - start.weekday()) % 7)  # first Monday
        weeks = []
        while cur + dt.timedelta(days=6) <= end:  # complete weeks only
            weeks.append((cur.isoformat(), sum(days.get((cur + dt.timedelta(days=i)).isoformat(), 0) for i in range(7))))
            cur += dt.timedelta(days=7)
        out[n] = dict(pkg=p, weeks=weeks)
    return out


if __name__ == '__main__':
    data = dict(collected=dt.date.today().isoformat(), repos=repos(), npm=npm(), commits=commits(),
                others=others(), downloads=downloads())
    json.dump(data, open(sys.argv[1] if len(sys.argv) > 1 else 'data.json', 'w'), indent=1)
