#!/usr/bin/env python3
"""Generate the agentic protocol capability map as a self-contained HTML page.

Edit ROWS below to change which protocol covers which capability, then run:

    python3 generate.py [output.html]

Box colour is derived from the data, so it cannot drift from the chips:
  - two or more full owners (F)         -> overlap (red)
  - one owner plus partial owners (P)   -> partial overlap (amber)
  - no owners                           -> gap (dashed)
  - one owner                           -> single owner

Ratings are the author's assessment (October 2026). See README.md for rendering.
"""
import sys
import html
# protocol -> colour
COL={'A2A':'#2f7fd1','KYA-OS':'#e0782a','AP2':'#2e9e6b','x402':'#8a56c2','MPP':'#c2398a','L402':'#b8960b','cheqd':'#1b8a8a',
     'ACP':'#6b7a8f','TAP':'#6b7a8f','KYAPay':'#c4572d','Baselayer':'#6b7a8f','MCP':'#2f7fd1'}
# (name, [(proto, level)], note)  level: F full, P partial
def cap(name, owners, gap=False): return dict(name=name, owners=owners, gap=gap)
ROWS=[
 ("Payment", [
   ("Payment authority", [
     cap("Mandate authorisation",[('AP2','F'),('ACP','P'),('TAP','P')]),
     cap("Spend limits and constraints",[('AP2','F')]),
     cap("Receipts and dispute evidence",[('AP2','F')]),
     cap("Binding the decision to the payment",[],True)]),
   ("Payment wire and settlement", [
     cap("HTTP-native payment request",[('x402','F'),('MPP','F'),('L402','F')]),
     cap("Session and streaming payments",[('MPP','F')]),
     cap("Card-rail payments",[('MPP','P'),('TAP','F'),('ACP','F')]),
     cap("Stablecoin settlement",[('x402','F'),('MPP','P')]),
     cap("Lightning settlement",[('L402','F')])]),
 ]),
 ("Identity and delegation", [
   ("Agent identity", [
     cap("Agent identity credential",[('KYA-OS','F'),('KYAPay','F'),('Baselayer','F')]),
     cap("Holder-of-key binding",[('KYA-OS','F'),('AP2','P')]),
     cap("Owner and deployer verification",[('Baselayer','F'),('KYAPay','F')])]),
   ("Delegation", [
     cap("Human-to-agent authority",[('KYA-OS','F'),('AP2','P')]),
     cap("Agent-to-agent delegation chain",[('KYA-OS','F')])]),
   ("Request proof", [
     cap("Per-request proof",[('KYA-OS','F'),('x402','P'),('L402','P')]),
     cap("Response proof",[('KYA-OS','P')]),
     cap("Replay protection",[('KYA-OS','F'),('x402','P')])]),
 ]),
 ("Discovery and transport", [
   ("Discovery", [
     cap("Agent discovery",[('A2A','F'),('KYA-OS','P')]),
     cap("Agent Card signature",[('A2A','P')]),
     cap("Skill and capability attestation",[],True)]),
   ("Interaction", [
     cap("Messages and tasks",[('A2A','F')]),
     cap("Tool and data access",[('MCP','F')]),
     cap("Extension negotiation",[('A2A','F')])]),
 ]),
 ("Trust anchor", [
   ("Resolution and linkage", [
     cap("DID resolution",[('cheqd','F'),('KYA-OS','P')]),
     cap("Reciprocal did:web and did:cheqd linkage",[('cheqd','F')]),
     cap("Versioned policy artefacts",[('cheqd','F')])]),
   ("Status", [
     cap("Credential status and revocation",[('cheqd','F'),('KYA-OS','P')]),
     cap("Trust registry standing",[('cheqd','F')])]),
 ]),
]
def kind(c):
    if c['gap']: return 'gap'
    full=[p for p,l in c['owners'] if l=='F']
    if len(full)>=2: return 'overlap'
    return 'partial' if len(c['owners'])>=2 else 'single'
stats={'gap':[], 'overlap':[], 'partial':[], 'single':[]}
def box(c):
    k=kind(c); stats[k].append(c['name'])
    chips=''.join(f'<span class="chip{" p" if l=="P" else ""}" style="--c:{COL[p]}">{html.escape(p)}{"" if l=="F" else " ◐"}</span>' for p,l in c['owners'])
    if c['gap']: chips='<span class="chip none">no owner</span>'
    return f'<div class="cap {k}"><div class="n">{html.escape(c["name"])}</div><div class="chips">{chips}</div></div>'
rows=''
for rname, groups in ROWS:
    g=''.join(f'<div class="grp"><div class="gt">{html.escape(gn)}</div><div class="caps">{"".join(box(c) for c in cs)}</div></div>' for gn,cs in groups)
    rows+=f'<div class="row"><div class="rl">{html.escape(rname)}</div><div class="groups">{g}</div></div>'
legend=''.join(f'<span class="chip" style="--c:{COL[p]}">{p}</span>' for p in ['A2A','MCP','KYA-OS','KYAPay','AP2','x402','MPP','L402','cheqd'])+'<span class="chip" style="--c:#6b7a8f">ACP / TAP / Baselayer</span>'
page=f'''<!doctype html><meta charset=utf-8><style>
body{{margin:0;padding:24px;background:#fff;font-family:Helvetica,Arial,sans-serif;color:#222;width:1560px}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{font-size:12px;color:#555;margin-bottom:14px}}
.row{{display:flex;gap:14px;margin-bottom:12px}}
.rl{{width:110px;font-weight:700;font-size:14px;padding-top:10px}}
.groups{{flex:1;display:flex;gap:10px}}
.grp{{flex:1;background:#faebcc;border:2px solid #444;border-radius:10px;padding:6px 8px 10px}}
.gt{{text-align:center;font-weight:700;font-size:12px;margin-bottom:6px}}
.caps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}}
.cap{{background:#f5dc9c;border:2px solid #444;border-radius:8px;padding:6px 6px 7px;text-align:center;min-height:62px}}
.cap .n{{font-size:12px;margin-bottom:5px;line-height:1.2}}
.cap.overlap{{border-color:#d32f2f;border-width:3px;background:#fde3d0}}
.cap.partial{{border-color:#e69500;border-width:3px;background:#fff1d6}}
.cap.gap{{border:2px dashed #888;background:#eee}}
.chips{{display:flex;flex-wrap:wrap;gap:3px;justify-content:center}}
.chip{{background:var(--c);color:#fff;border-radius:9px;font-size:10px;font-weight:700;padding:2px 7px;display:inline-block}}
.chip.p{{background:#fff;color:var(--c);border:1.5px solid var(--c);padding:1px 6px}}
.chip.none{{background:#888}}
.leg{{margin-top:14px;font-size:11px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}}
.k{{display:inline-block;width:14px;height:14px;border-radius:3px;margin:0 3px 0 10px;vertical-align:middle}}
</style>
<h1>Agentic protocol capability map</h1>
<div class="sub">Which protocol owns each capability. Red = two or more full owners (overlap). Amber = one owner plus partial coverage. Dashed = gap. Filled chip = owns, outlined chip with ◐ = partial. Author's assessment, October 2026; payment-protocol details are from secondary sources.</div>
{rows}
<div class="leg">{legend}
<span class="k" style="background:#fde3d0;border:3px solid #d32f2f"></span>overlap (two or more full owners)
<span class="k" style="background:#fff1d6;border:3px solid #e69500"></span>one owner plus partial coverage
<span class="k" style="background:#f5dc9c;border:2px solid #444"></span>single owner
<span class="k" style="background:#eee;border:2px dashed #888"></span>gap (no owner)</div>'''
out=sys.argv[1] if len(sys.argv)>1 else 'capability-map.html'
open(out,'w').write(page)
print({k:len(v) for k,v in stats.items()})
