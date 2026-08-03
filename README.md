# Gateway Runtime

Gateway 运行时数据面，使用 Go 和 CloudWeGo Hertz 实现。它从 Gateway Admin 拉取已生效配置，对进入 `/api/{service}/{path}` 的请求完成 HMAC 验签、路由匹配和上游转发，不提供配置管理 API。

## 启动

```bash
cp .env.example .env
go run ./cmd/server
```

默认监听 `:8082`，每 5 秒从 `http://127.0.0.1:8083/api/v1/runtime/config` 刷新配置。

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

签名算法为 `Gateway-HMAC-SHA256`，共享密钥由 `GATEWAY_SIGNING_SECRET` 配置。请求必须携带：

```http
X-Gateway-Credential: orders
X-Gateway-Signature: <hex_hmac_sha256>
X-Gateway-Timestamp: <unix_seconds>
X-Gateway-Nonce: <at_least_16_characters>
X-Gateway-Content-SHA256: <lowercase_hex_sha256_of_body>
```

`X-Gateway-Credential` 必须等于路径中的 `{service}`。签名使用专用请求头，不占用标准 `Authorization`，因此业务认证信息可以继续转发到上游。规范请求由六行组成，末尾不附加换行：

```text
HTTP_METHOD
FULL_REQUEST_PATH
CANONICAL_QUERY
UNIX_TIMESTAMP
NONCE
LOWERCASE_SHA256_HEX_OF_BODY
```

查询参数按名称和值排序并使用 RFC 3986 编码。签名为 `hex(HMAC-SHA256(secret, canonical_request))`。默认允许 5 分钟时间偏差，并在窗口内拒绝重复 nonce。

开发时可生成一组签名请求头：

```bash
GATEWAY_SIGNING_SECRET=replace-with-a-long-random-secret \
go run ./cmd/sign -service orders -method GET -url 'http://localhost:8082/api/orders/orders/42?verbose=true'
```

## 验证

```bash
gofmt -w ./cmd ./internal
go test ./...
```
