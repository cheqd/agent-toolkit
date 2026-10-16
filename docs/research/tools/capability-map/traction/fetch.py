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
# Official repositories belong to the protocol's own organisation or named steward. Third-party repositories are
# hand-picked: for each protocol, up to three repositories that implement the protocol itself (an SDK, server,
# library or plugin), highest stars first, after setting aside applications that merely use the protocol and
# curated lists. GitHub has many more (see TOPICS), so these are examples, not a census.
OFF, TP = 'official', 'third-party'
OTHERS = {
    'A2A': [('a2aproject/a2a-python', OFF), ('a2aproject/a2a-js', OFF), ('a2aproject/a2a-java', OFF), ('a2aproject/a2a-go', OFF),
            ('a2aproject/a2a-dotnet', OFF), ('a2aproject/a2a-rs', OFF), ('a2aproject/a2a-samples', OFF), ('a2aproject/a2a-inspector', OFF),
            ('pydantic/fasta2a', TP), ('qntx-labs/ra2a', TP), ('vishalmysore/a2ajava', TP)],
    'MCP': [('modelcontextprotocol/typescript-sdk', OFF), ('modelcontextprotocol/python-sdk', OFF), ('modelcontextprotocol/java-sdk', OFF),
            ('modelcontextprotocol/go-sdk', OFF), ('modelcontextprotocol/csharp-sdk', OFF), ('modelcontextprotocol/rust-sdk', OFF),
            ('PrefectHQ/fastmcp', TP), ('mcp-use/mcp-use', TP), ('mark3labs/mcp-go', TP)],
    'x402': [('x402-foundation/wg-identity', OFF), ('solana-foundation/pay', TP), ('x402-rs/x402-rs', TP),
             ('google-agentic-commerce/a2a-x402', TP)],
    'UCP': [('Universal-Commerce-Protocol/python-sdk', OFF), ('Universal-Commerce-Protocol/js-sdk', OFF),
            ('Universal-Commerce-Protocol/samples', OFF), ('Universal-Commerce-Protocol/conformance', OFF),
            ('Universal-Commerce-Protocol/ucp-schema', OFF), ('NVIDIA-AI-Blueprints/Retail-Agentic-Commerce', TP),
            ('Shopify/ucp-cli', TP), ('magebitcom/magento2-universal-commerce-module', TP)],
    'AP2': [('solana-foundation/pay', TP), ('vishalmysore/ap2java', TP)],
    'ACP': [('NVIDIA-AI-Blueprints/Retail-Agentic-Commerce', TP), ('vercel/acp-handler', TP), ('nekuda-ai/ACP-Checkout-Gateway', TP)],
    'TAP': [('inflowpayai/inflow-node', TP)],
    'MPP': [('tempoxyz/mpp-specs', OFF), ('solana-foundation/pay', TP), ('faremeter/faremeter', TP)],
    'L402': [('lightninglabs/L402', OFF), ('lightninglabs/lightning-agent-tools', OFF), ('l402-protocol/l402', TP),
             ('ngx-l402/ngx-l402', TP), ('Fewsats/l402-python', TP)],
    'Web Bot Auth': [('vestauth/vestauth', TP), ('TecharoHQ/samesame', TP), ('regent-protocol/regent-httpsig', TP)],
    'x401': [('proof/x401-node', OFF), ('proof/x401-ruby', OFF), ('solidusnetwork/x401', TP), ('Shehryar/x401', TP)],
    'ANS': [('agentnameservice/ans-registry', OFF), ('ruvnet/Agent-Name-Service', TP), ('1amageek/ans-sdk-swift', TP)],
    'PAP': [('datalayer/personal-agent-protocol', TP), ('richardanaya/pi-poppy', TP), ('akshay5995/poppyseed', TP)],
    'KYAPay': [('skyfire-xyz/kyapay_a2a', OFF), ('tollstile/Tollstile', TP)],
}
# GitHub repositories tagged with each protocol's topic on 16 Oct 2026. Includes applications that only use the protocol.
TOPICS = {'MCP': ('model-context-protocol', 37653), 'x402': ('x402', 3827), 'A2A': ('a2a-protocol', 604), 'L402': ('l402', 110),
          'UCP': ('universal-commerce-protocol', 66), 'Web Bot Auth': ('web-bot-auth', 41), 'ACP': ('agentic-commerce-protocol', 27),
          'AP2': ('agent-payments-protocol', 19)}
# Packages per protocol, group and registry. For each registry and group the package with the most downloads in the last
# four weeks is charted, so a package and its dependencies are not counted twice.
PACKAGES = {
    'A2A': {OFF: {'npm': ['@a2a-js/sdk'], 'pypi': ['a2a-sdk'], 'crates': ['a2a-lf', 'a2a-pb']},
            TP: {'pypi': ['fasta2a'], 'crates': ['ra2a']}},
    'MCP': {OFF: {'npm': ['@modelcontextprotocol/sdk'], 'pypi': ['mcp'], 'crates': ['rmcp']},
            TP: {'pypi': ['fastmcp'], 'npm': ['mcp-use']}},
    'x402': {OFF: {'npm': ['x402', '@x402/core', '@x402/extensions', '@x402/fetch', '@x402/mcp'], 'pypi': ['x402']},
             TP: {'crates': ['x402-types', 'x402-chain-eip155']}},
    'UCP': {OFF: {'npm': ['@ucp-js/sdk'], 'pypi': ['ucp-sdk'], 'crates': ['ucp-schema']}, TP: {'npm': ['@shopify/ucp-cli']}},
    'MPP': {OFF: {'npm': ['mppx'], 'pypi': ['pympp', 'pytempo']}, TP: {}},
    'Web Bot Auth': {OFF: {'npm': ['web-bot-auth', 'http-message-sig', 'jsonwebkey-thumbprint'], 'crates': ['web-bot-auth']},
                     TP: {'npm': ['vestauth', 'samesame'], 'pypi': ['regent-httpsig']}},
    'KYA-OS': {OFF: {'npm': ['@kya-os/mcp', '@kya-os/mcp-i']}, TP: {}},
    'x401': {OFF: {'npm': ['@proof.com/x401-node']}, TP: {'npm': ['@solidus-network/x401']}},
    'PAP': {OFF: {}, TP: {'npm': ['@datalayer/personal-agent-protocol', 'poppyseed'], 'pypi': ['personal-agent-protocol']}},
    'L402': {OFF: {'npm': ['@lightninglabs/l402', '@lightninglabs/lightning-mcp-server']}, TP: {'pypi': ['l402']}},
    'ACP': {OFF: {}, TP: {'npm': ['agentic-commerce-protocol', 'acp-handler'], 'pypi': ['agentic-commerce-protocol']}},
    'KYAPay': {OFF: {'npm': ['@skyfire-xyz/skyfire-seller-sdk-node']}, TP: {'npm': ['@tollstile/kyapay']}},
    'TAP': {OFF: {}, TP: {'npm': ['@inflowpayai/tap-seller']}},
}
# Publishers worth naming next to a charted package.
PUBLISHER = {'fasta2a': 'Pydantic', 'agentic-commerce-protocol': 'Svix', 'acp-handler': 'Vercel', '@shopify/ucp-cli': 'Shopify',
             'l402': 'Fewsats', '@datalayer/personal-agent-protocol': 'Datalayer', 'personal-agent-protocol': 'Datalayer',
             'poppyseed': 'a community developer', '@inflowpayai/tap-seller': 'InFlow', '@tollstile/kyapay': 'Tollstile',
             'mppx': 'wevm, with Tempo', 'pympp': 'Tempo', 'pytempo': 'Tempo', 'vestauth': 'the dotenv author', 'fastmcp': 'Prefect',
             '@skyfire-xyz/skyfire-seller-sdk-node': 'Skyfire'}
# Protocols where no package was found on npm, PyPI or crates.io, with what was checked.
NO_PACKAGE = {'AP2': 'The ap2 package on PyPI belongs to an unrelated project; no other package found on npm, PyPI or crates.io',
              'ANS': 'No package found on npm, PyPI or crates.io (Go reference implementation, Swift SDK)'}


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
    out, cache = {}, {}
    for proto, repos in OTHERS.items():
        for r, scope in repos:
            if r in cache:  # a repository can serve several protocols (e.g. solana-foundation/pay)
                out.setdefault(proto, []).append(dict(cache[r], scope=scope))
                continue
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
            rec = dict(repo=r, stars=j['stargazers_count'], created=j['created_at'][:10], pushed=j['pushed_at'][:10],
                       commits52w=sum(v for _, v in weeks) if weeks else None, weeks=weeks, archived=j['archived'])
            cache[r] = rec
            out.setdefault(proto, []).append(dict(rec, scope=scope))
    return out


def _week_starts(n=12):
    end = dt.date.today() - dt.timedelta(days=1)
    end -= dt.timedelta(days=(end.weekday() + 1) % 7)  # last Sunday on or before yesterday
    return [end - dt.timedelta(days=7 * i + 6) for i in range(n - 1, -1, -1)]


def _daily_once(registry, name):
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


def _daily(registry, name):
    for attempt in range(4):  # the registries rate-limit and fail intermittently
        days = _daily_once(registry, name)
        if days:
            return days
        time.sleep(3 * (attempt + 1))
    return None


def downloads():
    starts = _week_starts()
    out, cache = {}, {}
    for proto, groups in PACKAGES.items():
        out[proto] = {}
        for group, regs in groups.items():
            out[proto][group] = {}
            for registry, names in regs.items():
                best = None
                for name in names:
                    if (registry, name) not in cache:
                        days = _daily(registry, name)
                        cache[(registry, name)] = None if not days else [
                            sum(days.get((w + dt.timedelta(days=i)).isoformat(), 0) for i in range(7)) for w in starts]
                    weeks = cache[(registry, name)]
                    if not weeks:
                        continue
                    if best is None or sum(weeks[-4:]) > sum(best['weeks'][-4:]):
                        best = dict(package=name, weeks=weeks, publisher=PUBLISHER.get(name), candidates=len(names))
                if best:
                    best['monthly'] = sum(best['weeks'][-4:])
                    out[proto][group][registry] = best
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
                others=others(), topics=TOPICS, downloads=downloads())
    json.dump(data, open(sys.argv[1] if len(sys.argv) > 1 else 'data.json', 'w'), indent=1)
