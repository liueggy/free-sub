# free-sub

免费节点池的每日自动实测订阅。GitHub Actions 每天 04:17 (CST) 抓取源订阅，用 mihomo 逐节点实测，
只把**当前能连**的节点写进下面三份文件。

## 订阅地址

- Clash / Mihomo / Stash：`clash.yaml`
- Surge：`surge.conf`
- Shadowrocket / Quantumult（base64）：`nodes.txt`

raw:
```
https://raw.githubusercontent.com/liueggy/free-sub/main/clash.yaml
https://raw.githubusercontent.com/liueggy/free-sub/main/surge.conf
https://raw.githubusercontent.com/liueggy/free-sub/main/nodes.txt
```

jsDelivr（国内更快）:
```
https://cdn.jsdelivr.net/gh/liueggy/free-sub@main/clash.yaml
```

## 说明

- 只收录实测通过 `generate_204` 的节点，失效节点会被自动剔除
- 节点来自公开免费池，**不要用来登录银行/邮箱等敏感账号**
- 手动刷新：Actions → update-subscription → Run workflow
