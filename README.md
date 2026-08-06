# Gateway Runtime

Gateway 运行时数据面，使用 Go 和 CloudWeGo Hertz 实现。它从 Gateway Admin 拉取已生效配置，对进入 `/api/{audience}/{service}/{path}` 的请求完成身份认证、路由匹配和上游转发，不提供配置管理 API。

## 启动

```bash
cp .env.example .env
go run ./cmd/server
```

`GATEWAY_SIGNIN_ACCESS_KEY` 和 `GATEWAY_SIGNIN_SECRET_KEY` 必须配置为 Gateway 服务调用 Sign-in Inner 接口所用的服务 AK/SK；缺少时运行时会拒绝启动。`SIGNIN_INNER_URL` 指向 Gateway 自身地址，凭据解析和 STS 交换必须经过已注册的 `/api/inner/signin/**` 路由，不能绕过 Inner 配置直连 Sign-in。

默认监听 `:8082`，每 5 秒从 `http://127.0.0.1:8083/api/v1/runtime/config` 刷新配置。Gateway 通过 `GATEWAY_RUNTIME_TOKEN` 访问该接口，值必须与 Gateway Admin 保持一致。

## 请求格式

请求必须使用以下路径：

```text
/api/{audience}/{service}/{path}
```

例如服务编码为 `orders`，路由匹配路径为 `/orders/:id`，调用地址为：

```text
GET /api/inner/orders/orders/42
```

`audience` 只能是 `inner` 或 `open`。服务和路由配置按受众完全隔离，同一服务编码可在两个受众中指向不同上游。Gateway 使用当前受众匹配到的 `upstreamPath` 替换路径参数，保留原始查询参数，并将请求转发到服务的 `baseUrl`。

## 请求签名

签名算法为 `Gateway-HMAC-SHA256`。调用方服务在 Gateway Console 中生成自己的 AK/SK，请求必须携带：

```http
X-Gateway-Credential: gwak_<caller_access_key>
X-Gateway-Signature: <hex_hmac_sha256>
X-Gateway-Timestamp: <unix_seconds>
X-Gateway-Nonce: <at_least_16_characters>
X-Gateway-Content-SHA256: <lowercase_hex_sha256_of_body>
```

Inner 请求的 `X-Gateway-Credential` 填调用方 Inner 服务的 AK，路径中的 `{service}` 是目标服务编码，两者相互独立。Gateway 按 AK 取得对应 SK 完成验签，匹配路由后还会确认该调用方服务已获得接口授权。Open 编程请求使用用户 AK/SK，只有匹配的 OpenAPI 路由已开启“编程访问”时才会放行；该开关默认关闭。普通浏览器 Open 请求不携带签名，不受编程访问开关影响，Gateway 使用自身服务 AK/SK 经过 Sign-in Inner 路由把 `CLOUD_SESSION` 换成短期 AK/SK。显式开启“匿名 Open 访问”的路由不要求云登录态，Gateway 直接使用自己的系统凭据签名上游；该能力只允许 Open 路由，用于 People 等独立登录系统。路由还可显式允许转发业务 Cookie 和 CSRF Header，供独立 Session 系统维持登录态，未开启时不会转发。

签名使用专用请求头，不占用标准 `Authorization`。规范请求由六行组成，末尾不附加换行：

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
go run ./cmd/sign -method GET -url 'http://localhost:8082/api/inner/orders/orders/42?verbose=true'
```

## 验证

```bash
gofmt -w ./cmd ./internal
go test ./...
```
