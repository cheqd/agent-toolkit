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
    data = dict(collected=dt.date.today().isoformat(), repos=repos(), npm=npm(), commits=commits())
    json.dump(data, open(sys.argv[1] if len(sys.argv) > 1 else 'data.json', 'w'), indent=1)
