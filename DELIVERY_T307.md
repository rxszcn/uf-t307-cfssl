# T307 交付说明：OCSP 状态应答按请求哈希算法不可查故障修复

## 1. 故障现象与排查路径（分层复现）

值守面板把查询不通的终端计为不可信来源，撤销感知的前闸落在 OCSP 状态应答环节。
现象归纳：

- 升级完成、CertID 哈希切到 SHA-256 的客户端群，对同一张证书一律收到**未授权（unauthorized）**应答；
- 未升级、仍用 SHA-1 的客户端群对同一张证书查询返回**正常状态应答**；
- 库内按该序列号核对，状态记录在库且现行有效；应答服务侧无异常日志、无报错；
- 故障与请求侧哈希算法强绑定，换一类客户端即复现；网关对失败查询自动回退旧算法重试，读数在两态之间抖动；
- 按网络抖动、缓存陈旧排查均未命中。

排查按"分层复现 → 沿应答检索链路核对 → 核对落库形态"推进：

1. 固定同一张证书（测试用 `ocsp/testdata/cert.pem`，序列号
   `1333308112180215502`），分别用 SHA-1 与 SHA-256 构造 RFC 6960 请求，复现应答差异（见第 6 节实测读数）。
2. 沿 `ocsp` 包状态应答的检索链路核对检索依据如何由请求字段得出。
3. 核对 `certdb` 包状态记录字段的既有落库形态。

## 2. 根因链（逐跳推导）

| 跳 | 位置 | 事实 |
|----|------|------|
| ① 请求字段随算法变化 | RFC 6960 CertID / `golang.org/x/crypto/ocsp.CreateRequest` | `IssuerKeyHash = Hash(签发者 SubjectPublicKeyInfo 中公钥 BIT STRING)`，哈希算法由请求方选择。SHA-1 请求得到 20 字节摘要，SHA-256 请求得到 32 字节摘要；同一签发者在两类客户端下投影天然不同。实测：SHA-1=`abce33cfe18e4f2eca9eca9ea275da1f063a1199`，SHA-256=`4fe2ca559feb7957d15f0452eaf2ef7316bd7e67946f05fe8720be00a3221d56`。 |
| ② 应答侧把请求哈希当 AKI 精确查库 | 修复前 `ocsp/responder.go` `DBSource.Response` | `aki := hex.EncodeToString(req.IssuerKeyHash)`，随后以 `(serial, aki)` 二元组调用 `Accessor.GetOCSP` 做相等匹配。 |
| ③ 落库 AKI 是写入侧/厂商口径，与请求哈希无关 | `cli/ocsprefresh/ocsprefresh.go`；外部厂商 CA 导入 | 自有链路落库的是 `hex(cert.AuthorityKeyId)`（证书 AKI 扩展，SHA-1 口径）；外部厂商 CA 导入的记录按厂商自身口径计算公钥标识。两者都不等于"SHA-256(签发者公钥)"。 |
| ④ 精确匹配 0 行 | `certdb/sql` `selectOCSPSQL` | `WHERE serial_number = ? AND authority_key_identifier = ?` 对 SHA-256 请求查不到任何行。 |
| ⑤ 0 行被翻译成未授权 | `DBSource.Response` → `Responder.ServeHTTP` | 返回 `ErrNotFound`，HTTP 层写出 `unauthorizedErrorResponse = 30 03 0a 01 06`（OCSP responseStatus = unauthorized(6)）。这是正常的"无记录"分支，不产生 error 级日志，故服务侧看似无异常。 |
| ⑥ SHA-1 群正常、网关抖动 | 同上 | 未升级客户端的 SHA-1 投影恰好等于落库 AKI（第 ③ 跳的 SHA-1 口径），精确命中；网关 SHA-256 失败后回退 SHA-1 重试又命中，于是同一终端读数在 unauthorized 与正常 DER 之间抖动。 |

结论：故障不在网络、不在缓存、不在应答签名，而在**状态应答检索把"随请求哈希算法变化的 IssuerKeyHash"误当作与算法无关的存储键**，属于检索依据口径错误。

## 3. 设计取舍与理由

### 3.1 统一检索依据：序列号为唯一与哈希算法无关的关联键

RFC 6960 请求中只有序列号（CertID 的 `serialNumber`）不随请求方选择的哈希算法变化；
`issuerNameHash`、`issuerKeyHash` 都是选定哈希函数的输出。因此把检索主键统一到序列号：

- `certdb.Accessor` 新增 `GetOCSPBySerial(serial)`，返回该序列号下的**全部**记录，不参与 AKI 相等判断；
- `ocsp.DBSource.Response` 改为只按序列号取记录，再在返回集合中选**过期时间最晚（furthest-future expiry）的现行记录**——该"最晚到期即现行"的选择规则沿用修复前 `Response` 内既有逻辑，未引入新语义。

### 3.2 库内既有记录的兼容：零迁移、零改写

- 不改表结构、不改写入路径、不回填任何历史记录。旧记录（SHA-1/AKI 口径）与厂商口径记录原样保留即全部可查。
- 旧的 `GetOCSP(serial, aki)` 精确查询方法保留不删，仍服务于已持有确切存储 AKI 的调用方（`ocspstapling`、`api/revoke` 等），避免扩大影响面；仅应答检索这一职责面切换到新方法。
- 同序列号多份记录（轮换期重发布）天然被"取全部 + 最晚到期"覆盖，现行应答只有一份且确定。

### 3.3 取舍说明

- 序列号在单 CA 域内唯一；跨 CA 的序列号碰撞不是本系统证书库的既有威胁模型，且修复前 `InMemorySource` 本就只按序列号检索，本次修复使 DB 后端与文件后端的关联语义一致。
- 未采用"请求侧同时算 SHA-1/SHA-256 多投影、逐投影回退查库"的方案：该方案无法覆盖厂商自定义口径（厂商口径可能既不是 SHA-1 也不是 SHA-256 投影），且把哈希族知识硬编码进检索层，未来 SHA-384/SHA-512 客户端升级还会再次踩坑。序列号方案对哈希算法完全免疫。

## 4. 改动文件清单（仅限 ocsp / certdb / cli 三包）

| 文件 | 类型 | 改动 |
|------|------|------|
| `ocsp/responder.go` | 源码 | `DBSource.Response` 检索由 `GetOCSP(serial, 哈希派生AKI)` 改为 `GetOCSPBySerial(serial)`；移除不再使用的 `encoding/hex` 导入；补包注释与方法注释，写明按序列号关联的检索约定。 |
| `certdb/certdb.go` | 源码 | `Accessor` 接口新增 `GetOCSPBySerial(serial string) ([]OCSPRecord, error)`；为 `OCSPRecord` 及各字段补口径注释（AKI 为生产侧口径、与请求哈希无关；序列号为算法无关关联键）。 |
| `certdb/sql/database_accessor.go` | 源码 | 新增 `selectOCSPBySerialSQL` 常量与 `Accessor.GetOCSPBySerial` 实现；`GetOCSP` 原样保留。 |
| `cli/ocsprefresh/ocsprefresh.go` | 源码（仅注释） | 在 UpsertOCSP 落库处补注释，说明写入 AKI 采用证书自身 AuthorityKeyId 的生产侧口径，应答侧按序列号关联。 |
| `certdb/README.md` | 文档 | 新增"OCSP response records and lookup conventions"小节，对内说明两种 key identifier 口径的区别与按序列号检索的约定。 |
| `ocsp/responder_regression_test.go` | 新增测试 | 与 `ocsp` 包既有测试同目录、同框架（标准 `testing` + 既有 testdata/sqlite 基建）；含三组构造矩阵与边界断言，用例名均以 `TestOCSP` 前缀命中验收过滤模式。 |
| `certdb/sql/sql_test.go` | 测试 | 在既有 `testEverything` 框架中注册并新增 `testGetOCSPBySerial`，覆盖同序列号多口径记录并存、精确 AKI 查询落空而序列号查询命中、未知序列号返回空集。 |

`certdb.Accessor` 在全仓库（含 vendor）仅 `certdb/sql.Accessor` 一个实现，接口扩展无遗漏实现方；编译期断言 `var _ certdb.Accessor = &Accessor{}` 持续生效。

## 5. 边界情形与配套需求逐条对应

| 需求 | 对应改动 / 验证 |
|------|----------------|
| 同一序列号的现行状态应答不随请求方哈希算法变化，升级客户端群恢复可查 | `DBSource.Response` 只按序列号检索；回归 `TestOCSPHashAlgorithmIndependence/Group2_SHA256_request_standard_record`、`TestOCSPVendorKeyIdentifierRecord/current answer identical across request hashes...` 断言 SHA-1 与 SHA-256 路径返回字节级一致的同一份现行应答。 |
| 网关回退重试路径与直连路径应答语义一致 | 回归中 `regressionServe` 走完整 HTTP responder（等价网关/直连 HTTP 路径），并断言 HTTP 应答体与 `Source.Response` 直连查询结果字节一致、ETag 存在。 |
| 未升级客户端的既有查询读数保持不变 | 回归 Group 1 仍为 200 + 同一份成功 DER；既有 `TestSqliteTrivial`、`TestSqliteRealResponse`、`TestOCSP`、`TestCacheHeaders` 等全部保持通过。 |
| 厂商口径记录可查（第三组矩阵） | `TestOCSPVendorKeyIdentifierRecord/Group3_SHA256_request_vendor_record`：唯一记录的 AKI 与两种请求哈希均不相等，SHA-256 请求仍 200 取回该记录。 |
| 未知序列号仍回未授权 | `TestOCSPHashAlgorithmIndependence/unknown serial stays unauthorized`：断言 `ErrNotFound` 且 HTTP 应答体恰为 `30030a0106`。 |
| ocsp 包与 certdb 包对内说明文字与修复后检索约定一致 | 见第 4 节注释与 README 改动。 |
| 回归与 ocsp 既有测试同目录同框架、命名纳入验收过滤命中范围 | 新文件位于 `ocsp/`，用例名 `TestOCSPHashAlgorithmIndependence`、`TestOCSPVendorKeyIdentifierRecord` 均被 `-run "TestOCSP|..."` 命中（验收输出可见两个用例 PASS）。 |
| 改动范围限定 | 全部改动落在 ocsp、certdb、cli 三包内的源文件/测试文件/包内 README；未触碰迁移脚本与表结构。 |

## 6. 构造输入矩阵与实测读数

构造对象固定为同一张叶子证书（序列号 `1333308112180215502`），矩阵按"请求算法 × 签发者记录口径"推导为固定三组：

| 组 | 请求算法 | 库内记录口径 | 修复前读数 | 修复后读数 |
|----|----------|--------------|-----------|-----------|
| 组1 | SHA-1（IssuerKeyHash 20 字节 `abce33…1199`） | 标准口径记录（AKI=`abce33…1199`） | HTTP 200，应答体为成功 OCSP DER，前缀 `308202140a0100a0`（responseStatus=successful(0)，证书状态 Good） | 不变：HTTP 200 + 同一份成功 DER，前缀 `308202140a0100a0` |
| 组2 | SHA-256（IssuerKeyHash 32 字节 `4fe2ca…1d56`） | 同一条标准口径记录 | `Source.Response` 返回 `ErrNotFound: Request OCSP Response not found`；HTTP 200，应答体为未授权错误 DER `30030a0106`（responseStatus=unauthorized(6)），无成功应答体 | HTTP 200，应答体与组1字节一致的成功 DER，前缀 `308202140a0100a0`，`ParseResponse` 得状态 Good |
| 组3 | SHA-256（`4fe2ca…1d56`） | 厂商口径记录（AKI 与两种请求哈希均不相等） | `ErrNotFound` → 未授权 `30030a0106` | HTTP 200，成功取回厂商口径记录，前缀 `308202140a0100a0`，状态 Good；轮换并存场景下 SHA-1/SHA-256 两请求均拿到同一份最晚到期的现行记录 |

应答体形态说明：

- 成功应答：`SEQUENCE { OCSPResponseStatus(successful=0), responseBytes }`，DER 前缀固定 `30 82 .. .. 0a 01 00 a0 ..`，可被 `golang.org/x/crypto/ocsp.ParseResponse` 解析并读出证书状态；
- 未授权应答：仅 5 字节 `30 03 0a 01 06`，无 responseBytes，对应 RFC 6960 的 unauthorized(6)。

补充对照（未知序列号 `deadbeef`，SHA-256 请求）：修复前后均为 `ErrNotFound` + 未授权应答体 `30030a0106`，未授权语义保持不变。

## 7. 验收命令最终读数

环境说明：仓库的 sqlite 测试依赖 cgo（`mattn/go-sqlite3`），本机原无 C 编译器，已通过 winget 安装 WinLibs MinGW（gcc 16.2.0）并以 `CGO_ENABLED=1` + MinGW PATH 运行；验收命令本身（下列第一条）不含 sqlite 用例，在默认环境同样可跑。

```text
$ go test -count=1 ./ocsp/ -run "TestOCSP|TestOverrideHeaders|TestCacheHeaders|TestNewSourceFromFile|TestNewSignerFromFile|TestSign"
ok  	github.com/cloudflare/cfssl/ocsp	0.704s
```

命中并通过的用例（`-v` 实测）：
`TestNewSignerFromFile`、`TestSignNoResponder`、`TestSign`、`TestSignCustomInterval`、
`TestOCSPHashAlgorithmIndependence`（含 Group1/Group2/unknown-serial 子测）、
`TestOCSPVendorKeyIdentifierRecord`（含 Group3/跨算法跨路径一致性子测）、
`TestOCSP`、`TestOverrideHeaders`、`TestCacheHeaders`、`TestNewSourceFromFile` —— 零失败。

```text
$ go vet ./ocsp/... ./certdb/...
（无任何输出，零告警）
```

回归与既有测试全量读数（三包相关目录）：

```text
ok  github.com/cloudflare/cfssl/ocsp                  （含 TestSqliteTrivial / TestSqliteRealResponse 等既有 sqlite 用例）
ok  github.com/cloudflare/cfssl/certdb/dbconf
ok  github.com/cloudflare/cfssl/certdb/ocspstapling
ok  github.com/cloudflare/cfssl/certdb/sql            （含新增 testGetOCSPBySerial）
ok  github.com/cloudflare/cfssl/cli/ocsprefresh
```

`gofmt -l ocsp/ certdb/ cli/` 无输出。测试运行对两个 sqlite 数据文件（`ocsp/testdata/sqlite_test.db`、`certdb/testdb/certstore_development.db`）的写入均已用 `git checkout` 还原，未纳入改动集。

附注：`go build ./...` 在本机报 `transport/roots/system/root_windows.go` 若干 `undefined` 错误，经 `git stash` 回到干净基线复现，确认是仓库在 Windows 平台的既有问题，与本次改动无关；本次受限三包（ocsp/certdb/cli）及其全部依赖方（api、certinfo、signer 等）构建通过。
