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
         'PAP': 'personal-agent-protocol/personal-agent-protocol', 'KYAPay': 'skyfire-xyz/kyapay',
         'cheqd': 'cheqd/did-resolver'}
NPM = {'MCP': '@modelcontextprotocol/sdk', 'A2A': '@a2a-js/sdk', 'x402': 'x402', 'MPP': 'mppx',
       'Web Bot Auth': 'web-bot-auth', 'UCP': '@ucp-js/sdk', 'KYA-OS': '@kya-os/mcp', 'x401': '@proof.com/x401-node',
       'cheqd': '@cheqd/sdk'}


# Other repositories and packages for each protocol. They are not charted as series, but each chart lists them
# under "Not covered by this chart" so the single repository or package plotted is not mistaken for the whole ecosystem.
OTHERS = {
    'A2A': ['a2aproject/a2a-python', 'a2aproject/a2a-js', 'a2aproject/a2a-java', 'a2aproject/a2a-go', 'a2aproject/a2a-dotnet',
            'a2aproject/a2a-rs', 'a2aproject/a2a-samples', 'a2aproject/a2a-inspector'],
    'MCP': ['modelcontextprotocol/typescript-sdk', 'modelcontextprotocol/python-sdk', 'modelcontextprotocol/java-sdk',
            'modelcontextprotocol/go-sdk', 'modelcontextprotocol/csharp-sdk', 'modelcontextprotocol/rust-sdk'],
    'x402': ['google-agentic-commerce/a2a-x402', 'x402-foundation/wg-identity'],
    'UCP': ['Universal-Commerce-Protocol/python-sdk', 'Universal-Commerce-Protocol/js-sdk', 'Universal-Commerce-Protocol/samples',
            'Universal-Commerce-Protocol/conformance', 'Universal-Commerce-Protocol/ucp-schema'],
    'MPP': ['tempoxyz/mpp-specs'],
    'L402': ['lightninglabs/L402', 'lightninglabs/lightning-agent-tools'],
    'ANS': ['agentnameservice/ans-registry'],
    'PAP': ['datalayer/personal-agent-protocol', 'richardanaya/pi-poppy', 'akshay5995/poppyseed'],
    'x401': ['proof/x401-node', 'proof/x401-ruby'],
    'KYAPay': ['skyfire-xyz/kyapay_a2a'],
    'cheqd': ['cheqd/sdk', 'cheqd/did-provider-cheqd'],
}
OTHER_PACKAGES = [('MCP', 'mcp', 'PyPI'), ('A2A', 'a2a-sdk', 'PyPI'), ('x402', '@x402/core', 'npm'), ('x402', '@x402/fetch', 'npm'),
                  ('x402', 'x402', 'PyPI'), ('UCP', 'ucp-sdk', 'PyPI'), ('KYA-OS', '@kya-os/mcp-i', 'npm'),
                  ('cheqd', '@cheqd/sdk', 'npm'), ('cheqd', '@cheqd/did-provider-cheqd', 'npm')]


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
        for r in repos:
            j = gh(f'repos/{r}')
            if not j or 'stargazers_count' not in j:
                continue
            c = None
            for _ in range(6):
                d = gh(f'repos/{r}/stats/commit_activity')
                if isinstance(d, list) and d:
                    c = sum(w['total'] for w in d)
                    break
                time.sleep(3)
            out.setdefault(proto, []).append(dict(repo=r, stars=j['stargazers_count'], pushed=j['pushed_at'][:10],
                                                  commits52w=c, archived=j['archived']))
    return out


def other_packages():
    out = []
    for proto, name, registry in OTHER_PACKAGES:
        try:
            if registry == 'npm':
                u = 'https://api.npmjs.org/downloads/point/last-month/' + name.replace('/', '%2F')
                n = json.load(urllib.request.urlopen(u, timeout=30))['downloads']
            else:
                n = json.load(urllib.request.urlopen(f'https://pypistats.org/api/packages/{name}/recent', timeout=30))['data']['last_month']
        except Exception:
            continue
        out.append(dict(protocol=proto, package=name, registry=registry, monthly=n))
    return out


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
                others=others(), other_packages=other_packages())
    json.dump(data, open(sys.argv[1] if len(sys.argv) > 1 else 'data.json', 'w'), indent=1)
