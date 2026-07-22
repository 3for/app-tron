# ML-DSA-44 真机与私链端到端测试

本文说明如何在物理 Ledger 设备上运行 app-tron 的随机密钥
ML-DSA-44 PoC，并在开启 `allowMlDsa44` 的单节点 java-tron 私链上完成：

```text
生成随机 PQ 密钥 → 真机确认地址 → 私链账户转入测试 TRX
→ 真机审核并签名 → java-tron 本地验签 → 组装 PQAuthSig
→ broadcasthex 广播 → 查询链上 SUCCESS
```

以下主流程以 **Nano S+** 为例。当前 PoC 只用于互操作验证，不是可恢复的
生产钱包方案。

## 1. 重要限制

- PQ 私钥由设备随机生成，只保存在 Tron App 的 RAM 中。
- 退出 App、断电、设备重启、重新生成密钥或发生致命密码学错误后，私钥永久丢失。
- 同一会话中公钥和地址保持不变，但 ML-DSA 签名是随机化的，两次签名字节可以不同。
- 当前 `INS_SIGN_PQ` 只支持 `TransferContract`、`permission_id=0`，且交易
  `owner_address` 必须等于当前 PQ 地址。
- 本文的 witness/funding 私钥是公开测试数据，只能用于本地一次性私链。
- 不要把 `tests/private-chain/config.conf` 用于主网或公共测试网。
- 真机测试时不要传 `--apdu-tcp` 或 `--speculos-api-url`；这两个参数只用于模拟器。

为了避免中途丢失 PQ 私钥，从地址生成开始直到交易广播完成，设备必须保持连接、
解锁并停留在 Tron App 内。

## 2. 环境准备

需要：

- Docker
- Python 3
- JDK 17
- 当前 app-tron 仓库
- 支持 PQ 的 java-tron checkout，例如本文验证使用的
  `/Users/lanyu/zyd/java-tron-3for`
- 一台已开启开发者模式的 Ledger Nano S+

在 app-tron 仓库根目录创建主机端 Python 环境：

```sh
python3 -m venv /tmp/app-tron-pq-hardware-venv
source /tmp/app-tron-pq-hardware-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r tests/ragger/requirements.txt
```

Linux 还需要安装 Ledger udev rules，并确保当前用户能访问 USB 设备。macOS 上应
退出 Ledger Live，避免它占用设备连接。

设置 PQ java-tron 路径并编译其 `crypto` 模块：

```sh
export JAVA_TRON_DIR=/Users/lanyu/zyd/java-tron-3for
"$JAVA_TRON_DIR/gradlew" --no-daemon \
  -p "$JAVA_TRON_DIR" :crypto:classes
```

确认以下目录存在：

```sh
test -d "$JAVA_TRON_DIR/crypto/build/classes/java/main"
```

`tron-pq-verify` 会直接调用这里构建出的 java-tron `MLDSA44.verify`，而不是
使用 app-tron 自己的设备端验签结果。

## 3. 构建 Nano S+ ML-DSA PoC

使用已经验证的 API-26 Ledger builder 镜像：

```sh
docker run --rm \
  -v "$PWD:/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:1350bb805ce3f03a7cdf403de701c5e6aa5246c94fa251660f88949bea3c8638 \
  make BOLOS_SDK=/opt/nanosplus-secure-sdk \
       TARGET=nanos2 MLDSA_POC=1 -j2
```

构建成功后应生成：

```text
build/nanos2/bin/app.elf
build/nanos2/bin/app.apdu
```

如果遗漏 `MLDSA_POC=1`，安装的 App 不包含 PQ APDU，主机脚本会报告
ML-DSA PoC capability 不可用。

## 4. 将 PoC 侧载到物理设备

侧载前：

1. 确认恢复词已经安全备份。
2. 解锁 Ledger，停留在 dashboard，不要打开任何 App。
3. 关闭 Ledger Live 或其他可能占用 USB 的程序。
4. 确认设备允许安装开发者/非商店应用。

在主机 Python 环境中执行：

```sh
python -m ledgerblue.runScript --scp \
  --fileName build/nanos2/bin/app.apdu \
  --elfFile build/nanos2/bin/app.elf
```

根据设备屏幕提示批准安装。安装完成后，在设备上打开 `Tron` App，保持在
`Tron app is ready` 页面。

如果设备上已经安装同名正式版 Tron App，侧载可能要求先卸载或替换它。完成 PoC
测试后应恢复正式渠道版本。

## 5. 启动全新的 PQ 私链

私链 helper 会：

- 根据主机架构选择固定 digest 的 arm64/amd64 PQ1 java-tron 镜像；
- 只监听 `127.0.0.1:18090`；
- 使用一个固定 ECDSA witness 生产区块；
- 设置 `allowMultiSign=1`、`allowMlDsa44=1`；
- 将数据库放在仓库外的临时目录。

为本次测试选择一个新的空数据目录。不要复用来自其他配置的 java-tron 数据库：

```sh
export PQ_PRIVATE_DATA_DIR=/tmp/app-tron-pq-private-hardware-01
export PQ_PRIVATE_CONTAINER=app-tron-pq-private-hardware-01
tests/private-chain/run.sh start
```

首次启动可能需要等待数秒。检查 ML-DSA 链参数：

```sh
tests/private-chain/run.sh status | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(next(item for item in data["chainParameter"]
           if item["key"] == "getAllowMlDsa44"))
'
```

期望结果：

```text
{'key': 'getAllowMlDsa44', 'value': 1}
```

再确认 witness 正在持续出块：

```sh
curl -fsS -X POST http://127.0.0.1:18090/wallet/getnowblock \
  -H 'Content-Type: application/json' -d '{}' | python3 -c '
import json, sys
block = json.load(sys.stdin)
print("height=", block["block_header"]["raw_data"].get("number", 0))
'
```

等待约 3 秒后重复执行，高度应继续增加。如果节点未启动，查看：

```sh
tests/private-chain/run.sh logs
```

最后用主机驱动自身的前置检查再确认一次。这个命令不会连接 Ledger：

```sh
python tests/pq_hardware_nile.py \
  --node-url http://127.0.0.1:18090 \
  --check-chain
```

期望输出包含 `getAllowMlDsa44=1`。后续带 `--broadcast` 的真机命令也会在生成
PQ 密钥前和实际广播前各检查一次该参数。

## 6. 执行真机端到端交易

私链 genesis funding 账户为：

```text
Address:     TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp
Private key: 1234567890123456789012345678901234567890123456789012345678901234
```

它是公开测试凭据。主机脚本在本地签 funding 交易，只向节点发送签名后的交易，
不会把私钥提交给 java-tron HTTP API。脚本还会拒绝把该参数用于非 loopback 节点。

设置测试变量：

```sh
export TRON_PRIVATE_FUNDING_KEY=1234567890123456789012345678901234567890123456789012345678901234
export PQ_TEST_OUTPUT=/tmp/tron-mldsa-private-hardware
```

确认以下状态后再运行命令：

- 私链正在出块，且 `getAllowMlDsa44=1`；
- Ledger 已解锁；
- Tron PoC App 已打开；
- Ledger Live 已关闭；
- 从现在开始不要退出或重启 Tron App。

执行：

```sh
python -u tests/pq_hardware_nile.py \
  --node-url http://127.0.0.1:18090 \
  --to TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp \
  --amount-sun 1000000 \
  --minimum-balance-sun 10000000 \
  --private-chain-funding-key "$TRON_PRIVATE_FUNDING_KEY" \
  --java-tron-dir "$JAVA_TRON_DIR" \
  --output-dir "$PQ_TEST_OUTPUT" \
  --broadcast
```

### 第一次设备交互：确认 PQ 地址

脚本输出：

```text
Confirm the temporary ML-DSA-44 address on the Ledger device...
```

设备显示 `Verify temporary ML-DSA-44 address`。逐屏检查完整 TRON Base58 地址，
选择 `Approve`。批准后，终端会打印同一个地址，例如：

```text
Temporary PQ address: T...
Session: ........
Keep the Tron app open: this key is random, RAM-only, and unrecoverable.
```

随后脚本会自动完成：

1. 分片读取 1312 字节公钥；
2. 校验 `SHA256(public_key)` fingerprint；
3. 校验地址等于 `0x41 || Keccak256(public_key)[12..31]`；
4. 从固定私链账户向该 PQ 地址转入 10 TRX；
5. 等待 PQ 账户激活且余额达到 10 TRX。

期望终端输出：

```text
Private-chain funding accepted: <funding-txid>
Account activated=True, balance=10000000 SUN
```

### 第二次设备交互：审核 PQ 转账

脚本输出：

```text
Review and approve the transfer on the Ledger device...
```

设备上的关键字段应为：

```text
From:   刚刚确认的临时 PQ 地址
To:     TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp
Amount: 1 TRX
```

确认字段无误后选择签名。设备对
`SHA256(Transaction.raw_data)` 执行 pure ML-DSA-44、空 context 签名。

批准后，主机依次执行：

1. 分片读取 2420 字节签名；
2. 调用 `tron-pq-verify`，通过 java-tron `MLDSA44.verify` 验证；
3. 编码 `PQAuthSig { scheme=ML_DSA_44, public_key, signature }`；
4. 组装完整 `Transaction` protobuf；
5. 再次查询 `getAllowMlDsa44`；
6. 通过 `/wallet/broadcasthex` 广播。

成功输出类似：

```text
java-tron MLDSA44.verify: valid=true
Broadcast accepted: <pq-transaction-txid>
PQ key remains only while the Tron app stays open; it was not aborted.
```

## 7. 检查链上结果

从输出工件读取 txid：

```sh
export PQ_TXID="$(python3 -c '
import json, os
from pathlib import Path
print(json.loads((Path(os.environ["PQ_TEST_OUTPUT"]) / "summary.json").read_text())["txid"])
')"
echo "$PQ_TXID"
```

查询交易：

```sh
curl -fsS -X POST http://127.0.0.1:18090/wallet/gettransactionbyid \
  -H 'Content-Type: application/json' \
  -d "{\"value\":\"$PQ_TXID\"}" | python3 -c '
import json, sys
tx = json.load(sys.stdin)
print("txID=", tx.get("txID"))
print("contractRet=", tx.get("ret", [{}])[0].get("contractRet"))
print("pqScheme=", tx.get("pq_auth_sig", [{}])[0].get("scheme"))
'
```

期望：

```text
txID= <与 PQ_TXID 相同>
contractRet= SUCCESS
pqScheme= ML_DSA_44
```

再查询 transaction receipt，确认交易已经进入区块，并检查实际带宽消耗：

```sh
curl -fsS -X POST http://127.0.0.1:18090/wallet/gettransactioninfobyid \
  -H 'Content-Type: application/json' \
  -d "{\"value\":\"$PQ_TXID\"}" | python3 -c '
import json, sys
info = json.load(sys.stdin)
receipt = info.get("receipt", {})
print("blockNumber=", info.get("blockNumber"))
print("net_usage=", receipt.get("net_usage", 0))
print("net_fee=", receipt.get("net_fee", 0))
'
```

`blockNumber` 应为正数。使用本文固定配置和当前交易结构时，实测
`net_usage=3943`、`net_fee=0`；`net_usage` 可能因 java-tron 序列化内容变化而有
小幅变化，不应把 3943 写成硬编码断言。

查询 PQ 账户余额。`summary.json` 中保存的是 21 字节 hex 地址：

```sh
export PQ_ADDRESS_HEX="$(python3 -c '
import json, os
from pathlib import Path
print(json.loads((Path(os.environ["PQ_TEST_OUTPUT"]) / "summary.json").read_text())["address_hex"])
')"

curl -fsS -X POST http://127.0.0.1:18090/wallet/getaccount \
  -H 'Content-Type: application/json' \
  -d "{\"address\":\"$PQ_ADDRESS_HEX\",\"visible\":false}" | python3 -c '
import json, sys
account = json.load(sys.stdin)
print("balance=", account.get("balance", 0), "SUN")
print("owner_permission=", account.get("owner_permission"))
'
```

本流程先转入 10 TRX、再转出 1 TRX；在当前私链免费带宽足够的情况下，预期余额为：

```text
balance= 9000000 SUN
```

该预期依赖当前私链的 `getFreeNetLimit=5000`。如果修改私链资源参数或交易结构，
应以 receipt 的 `net_fee` 为准，余额可能低于 9000000 SUN；这不代表 ML-DSA
验签失败。

默认 Owner permission 的唯一 key 地址应等于 PQ 账户自身，这正是无需先发送
`AccountPermissionUpdateContract` 的原因。

## 8. 输出工件

`$PQ_TEST_OUTPUT` 包含：

| 文件 | 内容 |
| --- | --- |
| `raw_data.bin` | java-tron 构建的 `Transaction.raw_data` |
| `message_hash.bin` | `SHA256(raw_data.bin)`，设备实际签名消息 |
| `public_key.bin` | 1312 字节 ML-DSA-44 公钥 |
| `signature.bin` | 2420 字节 ML-DSA-44 签名 |
| `signed_transaction.bin` | 完整 protobuf Transaction |
| `signed_transaction.hex` | 可直接提交给 `broadcasthex` 的 hex |
| `summary.json` | 地址、txid、fingerprint 和广播结果摘要 |

可以独立重复 java-tron 验签：

```sh
"$JAVA_TRON_DIR/gradlew" --no-daemon \
  -p "$PWD/tron-pq-verify" \
  -PjavaTronDir="$JAVA_TRON_DIR" \
  run --args="$PQ_TEST_OUTPUT/public_key.bin $PQ_TEST_OUTPUT/message_hash.bin $PQ_TEST_OUTPUT/signature.bin"
```

期望：

```text
pk=1312 message=32 signature=2420 valid=true
```

## 9. 通过标准

一次完整测试同时满足以下条件才算通过：

- 设备本人确认的 PQ 地址与主机从 1312 字节公钥推导出的地址一致；
- java-tron `MLDSA44.verify` 对 32 字节 `message_hash.bin` 返回 `valid=true`；
- `broadcasthex` 返回 `result=true`，且返回 txid 与 `SHA256(raw_data.bin)` 一致；
- `gettransactionbyid` 返回同一 txid、`contractRet=SUCCESS`、
  `pqScheme=ML_DSA_44`；
- `gettransactioninfobyid` 返回正数 `blockNumber`；
- PQ 账户余额按 `转入 - 转出 - receipt.net_fee` 变化，Owner permission 的唯一
  key 地址等于 PQ 地址自身。

## 10. 会话与清理

脚本默认不会发送 `INS_ABORT_PQ_SESSION`，因为测试完成后 PQ 地址通常还剩余
私链余额。只要 Tron App 保持打开，密钥仍可能用于同一会话内的后续签名；但当前
脚本每次启动都会生成新密钥，不提供旧 session 的恢复功能。

如果确定不再使用该临时地址，可以：

- 在第一次运行时增加 `--abort-after-success`，让成功广播后立即擦除密钥；或
- 测试完成后退出 Tron App/断开设备，RAM 密钥随之丢失。

这里丢失的只是一次性私链测试资产。不要在真实网络上采用这种随机、不可恢复的
账户流程。

停止并移除私链容器：

```sh
tests/private-chain/run.sh stop
```

`stop` 不删除 `$PQ_PRIVATE_DATA_DIR`，链上记录仍可通过使用同一目录重新启动节点
恢复。若要进行完全独立的新测试，换一个新的空目录和容器名即可。

## 11. 常见问题

### `No dongle found`

- 确认设备已连接并解锁；
- 确认 Tron App 已打开；
- 关闭 Ledger Live；
- Linux 检查 udev rules 和 USB 权限；
- 不要同时运行另一个访问 Ledger 的进程。

### `ML-DSA PoC capability is unavailable`

设备上安装的是普通构建。重新使用 `MLDSA_POC=1` 和 API-26 SDK 构建、侧载。

### `getAllowMlDsa44=0`

- 确认连接的是 `http://127.0.0.1:18090`；
- 确认使用本目录的 `config.conf`；
- 不要复用由其他配置初始化过的数据库，改用新的空 `PQ_PRIVATE_DATA_DIR`。

主机脚本在该值不是 1 时，会在生成设备密钥前拒绝 `--broadcast`。

### `java-tron crypto classes not found`

重新执行：

```sh
"$JAVA_TRON_DIR/gradlew" --no-daemon \
  -p "$JAVA_TRON_DIR" :crypto:classes
```

### 设备签名阶段超时

检查设备是否停在待确认页面。ML-DSA keygen/sign 比 ECDSA 慢，不要在运算期间退出
App。真机命令中不要添加 Speculos 的自动按键参数。

### funding 后脚本失败

不要退出 App，否则 funding 到临时 PQ 地址的私钥会丢失。当前脚本不能跨进程恢复
旧 session，因此应先查看错误并保留现场；对于本 PoC，最简单的处理通常是使用
新的私链数据目录重新开始。

### `broadcasthex` 返回 `NO_CONNECTION`

单节点私链必须设置 `node.rpc.minEffectiveConnection=0`。本目录的
`config.conf` 已包含该配置；确认没有启动到其他配置文件。

## 12. Speculos 对照测试（可选）

同一个主机脚本也能连接 Speculos。只有模拟器测试时才添加：

```text
--apdu-tcp 127.0.0.1:9999
--speculos-api-url http://127.0.0.1:5000
```

它们会启用自动模拟按键。物理设备测试必须省略这两个参数，确保地址和交易都由
用户本人在设备上确认。
