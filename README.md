# keyrotate

keyrotate 只使用 Python 标准库，读取密钥登记册和签名日志，把不同写法的时间与密钥材料归一化，计算指纹和密钥链，并判断每条签名的生效密钥与状态。

## 输入与运行

登记册路径由 --keys 指定，JSON 顶层包含 keys 数组；签名日志由 --signatures 指定，JSON 顶层包含 signatures 数组。报告写到 --out 指定的路径。

    python -m keyrotate.cli --keys demo/keys.json --signatures demo/signatures.json --out out/report.json

命令成功后会在标准输出打印一行摘要，包含签名总数、验签通过数和六种状态各自的数量。报告使用固定的顶层字段顺序和登记册输入顺序，因此同一输入重复运行的输出逐字节一致。

## 时间归一化

支持以下五种绝对时间表示：

- UTC 的 RFC 3339：2026-01-05T00:00:00Z
- 带数字偏移的 RFC 3339：2026-01-05T08:00:00+08:00、2026-02-27T21:00:00-04:00
- ISO 8601 基本格式：20260320T000000Z
- Unix 秒整数：1772323200
- 带小数秒的 RFC 3339：2026-01-04T23:59:59.500Z

所有时间都转换成 UTC，精度截到秒。小数秒直接截断，不四舍五入；例如 2026-01-04T23:59:59.500Z 归一为 2026-01-04T23:59:59Z。输出格式固定为 YYYY-MM-DDTHH:MM:SSZ。

## 密钥材料

encoding 决定 material_b64 的字母表：

- base64 使用 A-Za-z0-9+/
- base64url 使用 A-Za-z0-9-_

解码前先用 Python 的空白分割规则移除材料中的全部空白，空格、换行和制表符都会被去掉。两种字母表都允许带或不带 = 填充；缺少填充时按长度补齐后再解码。所有哈希都基于解码得到的原始字节，不能直接哈希 material_b64 字符串。

## 指纹与密钥链

指纹是解码后密钥材料的 SHA-256 摘要，取小写十六进制的前 16 个字符。

每个 key_id 单独维护一条链，并按 generation 从小到大计算：

- 第一代的 lineage 等于它自己的 fingerprint
- 后续每一代先把上一代 16 位十六进制 lineage 解码成 8 个原始字节，再拼上本代解码后的密钥材料，对拼接结果做 SHA-256，取小写十六进制前 16 位

因此，不同 key_id 即使登记了相同材料、具有相同指纹，只要链上的前代不同，lineage 也会不同。

## 世代归属

签名只提供 key_id 和签名时刻。程序先选出同一 key_id 下所有 not_before 小于等于 signed_at 的世代，再取其中 not_before 最晚的一代；如果 not_before 相同，取 generation 更大的一代。没有任何世代满足条件时，签名不能归属到具体密钥。

## 状态判定

状态按以下顺序判定，命中即停止：

1. key_id 不在登记册：unknown_key，定态字段为 key_id_absent
2. 没有任何一代在签名时刻前生效：not_yet_valid，decisive_at 取该 key_id 最早的 not_before
3. 生效代的 revoked_at 小于等于 signed_at：revoked
4. 生效代的 not_after 小于 signed_at：若 grace_until 大于等于 signed_at 则为 grace，否则为 expired
5. 其他情况：active

只有 active 和 grace 的 verified 为真。expired 的 overdue_seconds 是签名时刻减 not_after 的整数秒；其他状态该字段为 null。

所有边界都是闭区间：not_before 当刻生效，not_after 当刻仍有效，grace_until 当刻仍在宽限期，revoked_at 当刻已撤销。撤销只影响撤销时刻及之后的签名，不追溯撤销前的签名；一旦撤销条件命中，它优先于宽限期和过期判断。

## 报告结构

报告顶层固定包含三个键：

- signatures：与输入签名日志同序，每条含 sig_id、key_id、signed_at、state、verified、effective_key、effective_fingerprint、effective_lineage、decisive_field、decisive_at、overdue_seconds
- registry：与输入登记册同序，每条含 key_id、generation、fingerprint、lineage、not_before、not_after、grace_until、revoked_at
- summary：含 signatures、verified、by_state、generations，其中 by_state 固定包含六种状态

未归属具体世代时，effective_key、effective_fingerprint 和 effective_lineage 都是 null。登记册中原本为 null 的时间字段，归一化后仍为 null。

## 测试

    python -m unittest test_keyrotate -v
