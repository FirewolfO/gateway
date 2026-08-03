# Gateway Runtime

Gateway 运行时数据面，使用 Go 和 CloudWeGo Hertz 实现。它从 Gateway Admin 拉取已生效配置，对进入 `/api/{service}/{path}` 的请求完成 HMAC 验签、路由匹配和上游转发，不提供配置管理 API。

## 启动

```bash
cp .env.example .env
go run ./cmd/server
```

默认监听 `:8082`，每 5 秒从 `http://127.0.0.1:8083/api/v1/runtime/config` 刷新配置。Gateway 通过 `GATEWAY_RUNTIME_TOKEN` 访问该接口，值必须与 Gateway Admin 保持一致。

## 请求格式

外部请求必须使用以下路径：

```text
/api/{service}/{path}
```

例如服务编码为 `orders`，路由匹配路径为 `/orders/:id`，调用地址为：

```text
GET /api/orders/orders/42
```

Gateway 使用匹配到的 `upstreamPath` 替换路径参数，保留原始查询参数，并将请求转发到服务的 `baseUrl`。

## 请求签名

签名算法为 `Gateway-HMAC-SHA256`。调用方服务在 Gateway Console 中生成自己的 AK/SK，请求必须携带：

```http
X-Gateway-Credential: gwak_<caller_access_key>
X-Gateway-Signature: <hex_hmac_sha256>
X-Gateway-Timestamp: <unix_seconds>
X-Gateway-Nonce: <at_least_16_characters>
X-Gateway-Content-SHA256: <lowercase_hex_sha256_of_body>
```

`X-Gateway-Credential` 填调用方服务的 AK，路径中的 `{service}` 是目标服务编码，两者相互独立。Gateway 按 AK 取得对应 SK 完成验签，成功后才检查目标服务路由。签名使用专用请求头，不占用标准 `Authorization`，因此业务认证信息可以继续转发到上游。规范请求由六行组成，末尾不附加换行：

```text
HTTP_METHOD
FULL_REQUEST_PATH
CANONICAL_QUERY
UNIX_TIMESTAMP
NONCE
LOWERCASE_SHA256_HEX_OF_BODY
```

查询参数按名称和值排序并使用 RFC 3986 编码。签名为 `hex(HMAC-SHA256(SK, canonical_request))`。默认允许 5 分钟时间偏差，并在窗口内按 AK 拒绝重复 nonce。通过验签后，Gateway 会向上游设置可信的 `X-Gateway-Caller-Service`，其值为 AK 所属服务编码。

开发时可生成一组签名请求头：

```bash
GATEWAY_ACCESS_KEY='gwak_...' GATEWAY_SECRET_KEY='gwsk_...' \
go run ./cmd/sign -method GET -url 'http://localhost:8082/api/orders/orders/42?verbose=true'
```

## 验证

```bash
gofmt -w ./cmd ./internal
go test ./...
```
