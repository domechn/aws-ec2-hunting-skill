# Exchange WebSocket targets: how to find, write and verify them

## What is measured

The **network segment**: candidate instance -> exchange gateway RTT. On every WebSocket connection the probe sends one
request per second and times "request sent -> matching response received" with a monotonic clock. Each connection has
at most one request in flight, so all it has to do is recognise "this frame answers the request I just sent".

## Choosing the method (in order of preference)

1. **Request/response with a correlation id** on the gateway. Examples: Binance WS API `depth` / `ping`,
   Bybit `{"op":"ping","req_id":...}`.
   Always compare **TCP handshake RTT** with **Req/resp RTT p50** in the smoke report: they should be the same order of magnitude.
   Binance market streams `LIST_SUBSCRIPTIONS` measured 47 ms RTT against 0.5 ms TCP on the same IPs: the control reply is delayed
   server-side, so it ranks nothing. Don't rank on such a method.
2. **Application-level text ping/pong** (`"ping"` -> `"pong"`) when the exchange echoes no id. Nothing else is subscribed on
   the connection, so nothing can be mistaken for the reply.
3. Don't use:
   - subscription pushes + exchange timestamps: the offset between the exchange clock and the local clock leaks into the result;
   - REST/HTTPS: usually a different gateway with different connection reuse;
   - signed/private calls: the probe doesn't handle API keys and doesn't need to.

Real market data is measured by a **feed target** (below), reported but never ranked: exchange timestamps have ms resolution
and include the clock offset. Rank on the gateway RTT instead. When orders go to a different host (Binance futures: market data on `fstream.binance.com`,
orders on `ws-fapi.binance.com`), add both as separate targets and give them the right roles in the goal.
When both legs share a host, one target can serve both roles.

## Researching an exchange that isn't in targets.example.json

1. WebSearch `<exchange> websocket api documentation`, and trust only official developer docs (e.g. `developers.binance.com`,
   `www.okx.com/docs-v5`, `bybit-exchange.github.io/docs`, `www.gate.io/docs/developers`, `www.bitget.com/api-doc`).
   Read the specific pages with WebFetch.
2. Find:
   - the production (not testnet) **public market-data** WebSocket base URL, with port and path, for the product the user wants;
   - the heartbeat / ping section: request format, response format, whether an id is echoed;
   - the cheapest unauthenticated request/response method;
   - rate limits: messages per connection per second, weight per IP per minute, connections per IP;
   - whether the exchange offers dedicated hosts for AWS / colo / market makers (verify they resolve on EC2 before using them).
3. Check rate limits: every instance opens one connection per resolved exchange IP, and every instance has its own public IP.
   Requests per IP = exchange IPs x (1000 / interval_ms). The default of 1 per second is far below every exchange's limit;
   weighted methods (such as depth) need their weight counted.
4. Write the target (format below), smoke test locally, then on EC2.

## Dedicated endpoints

Some users have endpoints the exchange provisioned just for them: VIP / market-maker hostnames, fixed IPs, PrivateLink
services, or VPC peering to the exchange.

- **Hostname** -> put it in `url`; the probe resolves it on the instance (private hosted zones resolve too, because the
  hunting subnets are in the user's VPC).
- **IPs only** -> keep the TLS hostname in `url` (SNI and certificate checks still use it) and list the IPs in `ips`.
- **Private path** -> PrivateLink endpoints in the VPC need no route, but their security group must admit the hunting
  subnets. Peering / Transit Gateway need `--route CIDR=pcx-...|tgw-...` at preflight; copy the CIDR and target from the
  route the user's production subnets already use (`aws ec2 describe-route-tables`).
- **Allowlisting** -> test instances get new public IPs every run; the skill pauses after deploy for the user to allowlist them.
- If a dedicated endpoint requires login before any ping is answered, the probe can't measure it. Tell the user and use the
  closest public host of the same exchange instead.

## Target format (targets.json is an array of these)

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Name in the report and the goal, e.g. `okx-swap-public` |
| `url` | yes | `wss://host[:port]/path`. The probe connects to each IP itself; TLS SNI and the Host header use this host |
| `request` | yes | Text frame to send; `{id}` is replaced by a unique 7-digit number |
| `match` | yes | Substring that identifies the reply; `{id}` is replaced the same way. Include the key, e.g. `"id":"{id}"`, `"req_id":"{id}"` |
| `interval_ms` | no | Send interval, default 1000 |
| `ips` | no | Fixed IPv4 list to test; default is every A record resolved on the instance |
| `kind` | no | `"tcp"`: only sample the TCP handshake RTT every `interval_ms` (no `request`/`match` needed). The default ranking metric |
| `subscribe` | feed only | Text frame that starts the stream, e.g. `{"method":"SUBSCRIBE","params":["btcusdt@bookTicker"],"id":1}` |
| `ts_key` | feed only | Top-level JSON key holding the exchange event time in **ms** (Binance `E`). Makes the target a feed: no `request`/`match` |

Quotes inside the JSON strings must be escaped; see `targets.example.json`. Match the id type to the docs: Binance market
streams want a number (`"id":{id}`), the Binance WS API a string (`"id":"{id}"`).

## Verification

- Local: `cargo run --release --manifest-path probe/Cargo.toml -- runs/targets.json 15`. A target passes when every row has
  `samples > 0`, `lost = 0` and `errors = 0`. Local networks may be geo-blocked or block ports such as 9443, so a local
  failure doesn't prove the target is wrong. The EC2 smoke test is the reference.
- EC2: `hunt.py run <run> runs/targets.json 30 --smoke`, then `hunt.py report <results-dir>` and read the detail table.

## Verified configs

All 11 targets in `targets.example.json` passed locally on 2026-10-27: Binance (futures WS API, futures market streams,
spot WS API, spot market streams), OKX public, Bybit linear/spot, Bitget public, Gate futures/spot, and Hyperliquid.
If one fails its smoke test, the API may have changed: re-research it as above.

## Known limits

- Text frames only. Exchanges that answer with gzip/binary frames (e.g. HTX) need a probe change.
- Exchanges behind a CDN (Bybit, Bitget and Hyperliquid via CloudFront; OKX via Cloudflare in some regions) are measured
  to the CDN edge, not to the matching engine. Placement differences are usually small there, so say so in the report.
- Exchange IPs change. The "best exchange IP" in the report is a point-in-time result; pinning it in production needs monitoring.
