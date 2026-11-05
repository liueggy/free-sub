#!/usr/bin/env python3
"""抓取订阅 -> 转 Clash -> mihomo 逐节点实测 -> 输出 clash/surge/base64 三份可用节点文件"""
import base64, concurrent.futures, json, os, re, subprocess, sys, time, urllib.parse, urllib.request

SUB_URL = os.environ.get('SUB_URL', 'https://proxypool1999.banyunxiaoxi.icu/')
TEST_URL = os.environ.get('TEST_URL', 'https://www.gstatic.com/generate_204')
MH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mihomo')
WORK = '/tmp/mhwork'
OUT = 'out'


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Surge/6.0 (iPhone; iOS 27.0)'})
    return urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'ignore')


def b64d(s):
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'ignore')


def qs(u):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query, keep_blank_values=True)
    return {k: v[0] for k, v in q.items()}


def parse_nodes(text):
    text = text.strip()
    if '://' not in text:
        text = b64d(text)
    out = []
    for i, l in enumerate([x.strip() for x in text.splitlines() if x.strip() and '://' in x], 1):
        scheme = l.split('://')[0].lower()
        frag = urllib.parse.unquote(l.split('#', 1)[1]) if '#' in l else ''
        label = frag.split('|')[0].strip()[:28]
        name = f"{i:03d} {label} [{scheme}]"
        body = l.split('#', 1)[0]
        p = None
        try:
            if scheme == 'ss':
                rest = body[5:]
                if '@' in rest:
                    head, hp = rest.rsplit('@', 1)
                    try:
                        cred = b64d(head)
                    except Exception:
                        cred = urllib.parse.unquote(head)
                    host, port = hp.split('?')[0].rsplit(':', 1)
                    meth, pwd = cred.split(':', 1)
                    p = dict(type='ss', server=host.strip('[]'), port=int(port), cipher=meth, password=pwd, udp=True)
                else:
                    cred, hp = b64d(rest).rsplit('@', 1)
                    meth, pwd = cred.split(':', 1)
                    host, port = hp.rsplit(':', 1)
                    p = dict(type='ss', server=host.strip('[]'), port=int(port), cipher=meth, password=pwd, udp=True)
            elif scheme == 'trojan':
                u = urllib.parse.urlparse(body)
                q = qs(body)
                p = dict(type='trojan', server=u.hostname, port=u.port or 443,
                         password=urllib.parse.unquote(u.username or ''), udp=True)
                if q.get('sni'):
                    p['sni'] = q['sni']
                if q.get('allowInsecure') in ('1', 'true'):
                    p['skip-cert-verify'] = True
            elif scheme == 'vless':
                u = urllib.parse.urlparse(body)
                q = qs(body)
                p = dict(type='vless', server=u.hostname, port=u.port or 443,
                         uuid=urllib.parse.unquote(u.username or ''), udp=True)
                sec = q.get('security', 'none')
                net = q.get('type', 'tcp')
                if sec in ('tls', 'reality'):
                    p['tls'] = True
                    p['servername'] = q.get('sni') or q.get('host') or u.hostname
                    if q.get('fp'):
                        p['client-fingerprint'] = q['fp']
                    if sec == 'reality':
                        ro = {}
                        if q.get('pbk'):
                            ro['public-key'] = q['pbk']
                        if q.get('sid'):
                            ro['short-id'] = q['sid']
                        if ro:
                            p['reality-opts'] = ro
                if q.get('flow'):
                    p['flow'] = q['flow']
                if net == 'ws':
                    p['network'] = 'ws'
                    ws = {'path': q.get('path', '/')}
                    if q.get('host'):
                        ws['headers'] = {'Host': q['host']}
                    p['ws-opts'] = ws
                elif net == 'grpc':
                    p['network'] = 'grpc'
                    p['grpc-opts'] = {'grpc-service-name': q.get('serviceName', '')}
                if q.get('allowInsecure') in ('1', 'true'):
                    p['skip-cert-verify'] = True
            elif scheme == 'vmess':
                d = json.loads(b64d(body[8:]))
                p = dict(type='vmess', server=d['add'], port=int(d['port']), uuid=d['id'],
                         alterId=int(d.get('aid', 0) or 0), cipher='auto', udp=True)
                if d.get('tls') == 'tls':
                    p['tls'] = True
                    if d.get('sni') or d.get('host'):
                        p['servername'] = d.get('sni') or d.get('host')
                if d.get('net') == 'ws':
                    p['network'] = 'ws'
                    p['ws-opts'] = {'path': d.get('path', '/'), 'headers': {'Host': d.get('host') or d['add']}}
            elif scheme in ('hysteria2', 'hy2'):
                u = urllib.parse.urlparse(body)
                q = qs(body)
                p = dict(type='hysteria2', server=u.hostname, port=u.port or 443,
                         password=urllib.parse.unquote((u.username or '') + (':' + u.password if u.password else '')),
                         udp=True)
                if q.get('sni'):
                    p['sni'] = q['sni']
                if q.get('insecure') in ('1', 'true'):
                    p['skip-cert-verify'] = True
                if q.get('obfs'):
                    p['obfs'] = q['obfs']
                    p['obfs-password'] = q.get('obfs-password', '')
        except Exception as e:
            print(f'  skip #{i}: {e}')
            continue
        if p:
            p['name'] = name
            p['_uri'] = l
            out.append(p)
    return out


def test_one(name, timeout=5000, api_timeout=15):
    q = urllib.parse.urlencode({'url': TEST_URL, 'timeout': timeout})
    u = 'http://127.0.0.1:9090/proxies/%s/delay?%s' % (urllib.parse.quote(name, safe=''), q)
    try:
        with urllib.request.urlopen(u, timeout=api_timeout) as r:
            return json.load(r).get('delay', 0) or 0
    except Exception:
        return 0


def main():
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    print('fetch', SUB_URL)
    nodes = parse_nodes(fetch(SUB_URL))
    print('parsed', len(nodes))
    if not nodes:
        print('no nodes, abort'); sys.exit(1)

    names = [n['name'] for n in nodes]
    cfg = {
        'mixed-port': 7899, 'allow-lan': False, 'mode': 'global', 'log-level': 'warning',
        'external-controller': '127.0.0.1:9090',
        'dns': {'enable': True, 'enhanced-mode': 'normal', 'use-hosts': True,
                'default-nameserver': ['223.5.5.5'], 'nameserver': ['1.1.1.1', '8.8.8.8']},
        'proxies': [{k: v for k, v in n.items() if not k.startswith('_')} for n in nodes],
        'proxy-groups': [{'name': 'ALLNODES', 'type': 'select', 'proxies': names}],
        'rules': ['MATCH,ALLNODES'],
    }
    cpath = os.path.join(WORK, 'config.json')
    json.dump(cfg, open(cpath, 'w'), ensure_ascii=False)

    proc = subprocess.Popen([MH, '-d', WORK, '-f', cpath],
                            stdout=open(os.path.join(WORK, 'mihomo.log'), 'w'),
                            stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(1)
        try:
            urllib.request.urlopen('http://127.0.0.1:9090/version', timeout=2).read()
            break
        except Exception:
            pass
    else:
        print('mihomo 启动失败'); proc.kill(); sys.exit(1)

    res = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        for n, d in zip(names, ex.map(lambda x: test_one(x, 5000, 15), names)):
            res[n] = d
    retry = [n for n in names if res[n] == 0]
    print('第一轮可用', sum(1 for v in res.values() if v), '| 重测', len(retry))
    if retry:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            for n, d in zip(retry, ex.map(lambda x: test_one(x, 8000, 20), retry)):
                res[n] = d
    proc.kill()
    ok = sum(1 for v in res.values() if v)
    print('最终可用', ok, '/', len(names))
    if ok == 0:
        print('全部失效，保留旧文件'); sys.exit(0)

    alive = [n for n in nodes if res[n['name']] > 0]
    alive.sort(key=lambda n: res[n['name']])
    seen, uniq = set(), []
    for n in alive:
        k = (n['server'], n['port'])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)

    # 1) clash
    cnames = [n['name'] for n in uniq]
    clash = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
        'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'default-nameserver': ['223.5.5.5'], 'nameserver': ['223.5.5.5', '119.29.29.29']},
        'proxies': [{k: v for k, v in n.items() if not k.startswith('_')} for n in uniq],
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO'] + cnames},
            {'name': 'AUTO', 'type': 'url-test', 'proxies': cnames, 'url': TEST_URL,
             'interval': 300, 'tolerance': 50}],
        'rules': ['GEOIP,CN,DIRECT', 'MATCH,PROXY'],
    }
    open(os.path.join(OUT, 'clash.yaml'), 'w').write(json.dumps(clash, ensure_ascii=False, indent=1))

    # 2) surge
    sp, sgl = [], []
    for n in uniq:
        nm = re.sub(r'[,\s#=]+', '_', n['name']).strip('_')
        t = n['type']
        if t == 'ss':
            line = f"{nm} = ss, {n['server']}, {n['port']}, encrypt-method={n['cipher']}, password={n['password']}"
        elif t == 'trojan':
            line = f"{nm} = trojan, {n['server']}, {n['port']}, password={n['password']}"
            if n.get('sni'):
                line += f", sni={n['sni']}"
            if n.get('skip-cert-verify'):
                line += ", skip-cert-verify=true"
        elif t == 'vmess':
            line = f"{nm} = vmess, {n['server']}, {n['port']}, username={n['uuid']}"
            if n.get('tls'):
                line += ", tls=true"
            if n.get('network') == 'ws':
                line += f", ws=true, ws-path={n.get('ws-opts',{}).get('path','/')}"
                h = n.get('ws-opts', {}).get('headers', {}).get('Host')
                if h:
                    line += f", ws-headers=Host:{h}"
        elif t == 'hysteria2':
            line = f"{nm} = hysteria2, {n['server']}, {n['port']}, password={n['password']}"
            if n.get('sni'):
                line += f", sni={n['sni']}"
            if n.get('skip-cert-verify'):
                line += ", skip-cert-verify=true"
        else:
            continue
        sp.append(line)
        sgl.append(nm)
    stamp = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())
    surge = f"""# 免费节点池实测可用版 — {stamp}
# {len(sgl)} 节点 / 源 {len(nodes)} 条，GitHub Actions 每日自动重测更新
[General]
loglevel = notify
dns-server = 223.5.5.5, 119.29.29.29
ipv6 = false
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local
bypass-system = true
internet-test-url = {TEST_URL}
proxy-test-url = {TEST_URL}

[Proxy]
""" + "\n".join(sp) + """

[Proxy Group]
PROXY = select, AUTO, """ + ", ".join(sgl) + """
AUTO = url-test, """ + ", ".join(sgl) + f""", url = {TEST_URL}, interval = 300, tolerance = 50

[Rule]
FINAL,PROXY
"""
    open(os.path.join(OUT, 'surge.conf'), 'w').write(surge)

    # 3) base64 原始节点
    uris = [n['_uri'] for n in uniq]
    open(os.path.join(OUT, 'nodes.txt'), 'w').write(base64.b64encode("\n".join(uris).encode()).decode())

    # 4) 人读清单
    rep = [f"# {stamp} 实测可用 {len(uniq)} 个（源 {len(nodes)} 条，{ok} 条连接成功）", '']
    from collections import Counter
    cnt = Counter(n['type'] for n in uniq)
    rep.append('协议分布: ' + ', '.join(f'{k} {v}' for k, v in cnt.most_common()))
    rep.append('')
    rep.append('| 延迟 | 名称 | 协议 | 地址 |')
    rep.append('|---|---|---|---|')
    for n in uniq[:40]:
        rep.append(f"| {res[n['name']]}ms | {n['name']} | {n['type']} | {n['server']}:{n['port']} |")
    open(os.path.join(OUT, 'README.md'), 'w').write("\n".join(rep) + "\n")
    print('输出完成:', len(uniq), '节点')


if __name__ == '__main__':
    main()
