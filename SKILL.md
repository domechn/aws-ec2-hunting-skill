---
name: ec2-hunting
description: One-click EC2 hunting for low-latency crypto trading. Launches test EC2 instances in the AZ IDs the user picks (each in its own cluster placement group), measures WebSocket RTT from every instance to every IP of every exchange endpoint (Binance, OKX, Bybit, Bitget, Gate, Hyperliquid, or an exchange-provided dedicated endpoint) for at least 5 minutes, ranks them against the user's goal (e.g. order leg first, market-data leg second), reports TCP/TLS/WebSocket-upgrade/RTT breakdowns, live market-data lag and the fastest endpoint IP per instance, then keeps the winners and terminates the rest, optionally over several elimination rounds. Use this whenever someone wants to find the fastest AWS placement, AZ or instance for an exchange, compare AZ latency to an exchange, pick a cluster placement group for a trading host, or mentions EC2 hunting, exchange latency testing, tick-to-trade network optimization, or market-making / HFT placement, in any language, even without the word "hunting".
---

# EC2 Hunting

Two instances of the same type in the same AZ can have different latency to an exchange, because latency belongs
to the physical placement (host, rack, network path). Hunting = launch many, measure, keep the fastest.

This skill only ever launches **test instances**. Each candidate gets **its own cluster placement group (CPG)**.
What the user takes away is the winner's CPG: production instances launched into it later land in the same
network segment. A PPG cannot give that: a running instance can't join a CPG without a stop/start, and stop/start
moves it to another host, which throws the measured placement away. Use this to explain the design if asked.

## Conventions

- `SKILL_DIR` = the directory of this file. Run everything from there; `HUNT="python3 scripts/hunt.py"`.
- Every Bash call is a fresh shell: prefix every `aws` / `hunt.py` command with `AWS_PROFILE=<p> AWS_REGION=<r>`.
- A run is one CloudFormation stack `ec2-hunt-<timestamp>` plus `runs/<stack>/` (config, cdk.out, results).
  Only resources inside that stack are ever created or deleted. Existing subnets, route tables and IGWs are never touched.
- Talk to the user in their language. Long steps (`deploy`, `run`) go through `run_in_background`; wait for the
  completion notification instead of polling.

## Workflow

### 1. Identity and region

1. `aws configure list-profiles`, then AskUserQuestion (with more than 4 profiles, list them in the question and let the user type one).
2. `$HUNT perms`: prints the account and identity, and simulates every IAM action the flow needs.
   On `FAIL`, show the denied actions and stop until the user fixes them or switches profile. On `WARN`, explain and ask.
   Mention it when the identity looks like Admin/Prod: the flow only adds resources, and deletes only its own stack.
3. Ask the region, default `ap-northeast-1` (Tokyo, where the major exchanges match).

### 2. AZ name <-> AZ ID, pick AZs

```bash
aws ec2 describe-availability-zones --filters Name=zone-type,Values=availability-zone \
  --query 'AvailabilityZones[].[ZoneName,ZoneId,State]' --output table
```

Show the table and explain: AZ names (`ap-northeast-1a`) are shuffled per account, AZ IDs (`apne1-az4`) are the same
physical location in every account, and exchanges talk in AZ IDs. AskUserQuestion (multiSelect) for the AZ IDs to test;
suggest all of them when the user doesn't know where the exchange sits.

### 3. Goal and endpoints: interview the user

Requirements differ a lot between users, so ask until all of this is clear. Never guess.

- **Exchanges and products** (spot / perpetual / delivery), and the **role of each**: market-data leg, order leg, or both.
- **Endpoint per exchange**: the public endpoint, or a **dedicated endpoint the exchange gave them** (VIP / market-maker /
  colo hostnames or IPs). For a dedicated endpoint also ask:
  - how it's reached: internet, PrivateLink, VPC peering or Transit Gateway. Private paths need a route
    (`--route CIDR=pcx-...|tgw-...` in preflight); PrivateLink needs nothing extra, but its endpoint security group must
    admit the hunting subnets;
  - whether it requires **source IP allowlisting**. Test instances get fresh public IPs, so step 8 will pause for it;
  - whether a plain ping works without login.
- **Ranking**: which leg comes first, and what counts as "about the same" (default 5%). Example: "OKX is the order leg,
  Binance the market-data leg" = fastest OKX first, then among candidates within 5% of it, the fastest Binance.
- **Hard limits** (optional), e.g. "OKX p50 must be under 800 us". Candidates over the limit are terminated even if they rank first.
- **Metric**: p50 by default; p99 if they care about the tail.
- **Rounds**: default 1 round. For a more reliable pick, run several elimination rounds (e.g. 3): every round adds fresh
  challengers next to the previous winners (step 12), tests them all in the same time window, and keeps the top N. Ask how many
  challengers per AZ each round adds and how many survive each round (e.g. keep 3 / 2 / 1); the survivors of the last round
  are the final winners. One round = one `keep` value, passed as `report --keep N`.

Write `runs/goal.json` (step 11 passes it to the report) and read it back to the user in plain words:

```jsonc
// 1. Lowest network round trip to the Binance futures order gateway (recommended default: TCP handshake RTT)
{"description": "Lowest TCP handshake RTT to Binance futures", "keep": 1,
 "tiers": [{"targets": ["binance-usdm-tcp"]}]}

// 2. OKX order leg first; within 5% of the best OKX, the fastest Binance
{"description": "OKX order leg first, then Binance", "keep": 1,
 "tiers": [{"targets": ["okx-public"], "tolerance_pct": 5}, {"targets": ["binance-usdm-api"]}]}

// 3. Both exchanges equally weighted, OKX must stay under 800 us p50, keep 2
{"description": "Balanced Binance + OKX", "keep": 2,
 "tiers": [{"targets": ["okx-public", "binance-usdm-api"], "max_us": 800}]}
```

**Default ranking metric: TCP handshake RTT** (`tcp` target, step 4). It is the pure network round trip, free of the exchange's own
processing, which varies and swamped placement differences (~0.65 ms of server time on top of ~0.3 ms network in the Binance tests).
Req/resp RTT and market-data lag stay in the report as context. Rank on a req/resp target only if the user asks for it, and
then on one whose reply comes straight from the exchange gateway. Control requests on some market-data hosts carry
server-side delay (Binance `fstream` `LIST_SUBSCRIPTIONS` answers in ~50 ms steps although TCP is 0.5 ms), which ranks noise.
Step 9 checks this. Real market data goes in as a `feed` target (step 4): reported, never ranked.

Fields: `tiers` is ordered by priority, and every tier except the last is a filter (within `tolerance_pct`). Several targets
in one tier are averaged as ratios to their best. `max_us` is a hard limit; `metric` is `p50`, `p95` or `p99`.

### 4. Targets

1. Start from `targets.example.json` (verified configs) and copy the needed entries into `runs/targets.json`.
2. For anything not in it, including dedicated endpoints, follow `references/exchanges.md`: read the exchange's official
   WebSocket docs, pick a request/response method, write the target. Never invent URLs or message formats from memory.
3. For a dedicated endpoint, set `url` to its hostname, or add `ips` when it was given as IPs.
4. **TCP target** (recommended, the default ranking metric): `{"name", "kind": "tcp", "url", "interval_ms": 500}`, see `binance-usdm-tcp`.
   It samples the TCP handshake (connect -> return, then close) of every endpoint IP every `interval_ms` for the whole run:
   min/p50/p95/p99 over ~600 samples per IP in 5 minutes. The startup-only 5 samples in the other tables are too few to rank on.
   Use the order gateway's host. Keep it light on the exchange: 2 connects per second per IP is plenty.
5. **Market data feed** (optional, recommended when a market-data leg matters): add a target with `subscribe` and `ts_key`
   instead of `request`/`match` (see `targets.example.json`, `binance-usdm-feed`). It subscribes to the live stream and reports
   local wall clock minus the exchange's event timestamp. Timestamps have ms resolution and include the clock offset, so it is
   read relatively (instance vs instance), never ranked.
6. Target names must match the goal file. If Rust is installed locally, smoke test:
   `cargo run --release --manifest-path probe/Cargo.toml -- runs/targets.json 15`
   (expect local failures for private or allowlisted endpoints; EC2 smoke in step 9 is the real check).

### 5. Instance parameters

- **Instance type**: default `m8azn.large` (2 vCPU = 2 full cores, no hyper-threads, so the RTT probe on CPU 1 and the feed on CPU 0
  never share a core; cluster placement groups supported, offered in all Tokyo AZs). Ask which type production will use, and prefer the same family: mixing types in a
  CPG raises the odds of capacity errors when production joins it later. T family is rejected (no CPG support).
- **Candidates per AZ**: default 7. The whole run must stay at or under about 33 candidates (CloudFormation inline template
  limit, which is what lets us skip `cdk bootstrap`). Split more into separate runs.
- **Duration**: default 300 s, never less than 300 (`hunt.py` refuses).
- **AMI**: ask with AskUserQuestion, options: "default: latest Amazon Linux 2023 (Recommended)" (SSM agent built in, chrony on
  Amazon Time Sync) or their own, entered as Other: an AMI id (`ami-...`, must be visible in the region and match the
  instance architecture) or an SSM public parameter path (e.g. Ubuntu: `/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id`).
  Pass it as `--ami` in step 6; omit `--ami` for the default. A custom AMI needs cloud-init and the SSM agent; Amazon Linux
  and Ubuntu qualify. Preflight pins the resolved AMI id and checks arch, state and the RunInstances dry run.
- **OS tuning**: none on purpose. All candidates run the same image and script at the same time, so OS noise is common to all
  of them and cancels out; the probe is pinned to one core.

### 6. VPC and preflight

1. `aws ec2 describe-vpcs --query 'Vpcs[].[VpcId,CidrBlock,IsDefault,Tags[?Key==\`Name\`]|[0].Value]' --output table`, ask which VPC.
2. `$HUNT preflight <vpc-id> <type> <per-az> <az-id>... [--secs N] [--ami ...] [--route CIDR=pcx-...]`. It checks:
   VPC DNS, the IGW (reused if attached, never modified), IGW ingress routing (appliance on the return path),
   the default NACL, free /27 per AZ, instance type offered per AZ, vCPU quota, the AMI (arch, state), a RunInstances dry run (catches SCPs), and price.
   It then creates `runs/<stack>/config.json`.
3. Show every line. `FAIL` = stop and fix. `WARN` = explain and let the user decide.

The hunting subnets route `0.0.0.0/0` straight to the IGW. No NAT gateway: behind a NAT every candidate would exit through the
same NAT, so the test would measure the NAT's placement, not each instance's. A NAT also adds a hop, jitter and per-GB
charges. Explain this if the user asks why their existing (NAT) subnets aren't used.

### 7. Confirm before anything is created

One AskUserQuestion (options: start / change parameters / cancel) whose text covers:

- What gets created in which VPC: N x `<type>` (one CPG each), one /27 subnet per AZ, a route table, a security group
  (egress only), an IAM role + instance profile (SSM only), and an IGW only if the VPC has none. Nothing existing is modified.
- Cost: `estimated_run_usd` from preflight (instances + public IPv4, about `hours` hours), or "see On-Demand pricing" if the lookup failed.
- Timeline: about 5-8 min deploy + build, 1 min smoke, then the test duration, then the report.
- **After the test, candidates that don't meet the goal are terminated automatically**; the top `keep` stay running and
  keep billing (`kept_winner_usd_per_hour` each) until the user destroys the run.
- If an endpoint needs allowlisting, the run will pause after deploy for the user to allowlist the instance IPs.

Only continue on an explicit "start".

### 8. Deploy

`$HUNT deploy runs/<stack>` (background). It synthesizes the CDK app, checks the template size and deploys with the caller's
credentials. No `cdk bootstrap` and no S3: the probe source ships gzipped in the launch template's user data. It prints the
candidates. If some fail with `InsufficientInstanceCapacity`, AWS had no capacity right then (not a quota issue):
`$HUNT destroy runs/<stack>` and retry, or use fewer candidates in that AZ.

If an endpoint needs allowlisting: give the user the `public_ip` list and wait until they confirm it's allowlisted.

### 9. Smoke test (first candidate, 30 s)

Besides samples and errors, check the new columns: **TCP handshake RTT** is the pure network round trip, **TLS** and **WS upgrade** about one
round trip each (plus processing). If **Req/resp RTT** p50 is more than ~5x the TCP handshake RTT for a ranked target, the reply is delayed by the exchange itself
(wrong method for ranking): pick another request, see `references/exchanges.md`.

`$HUNT run runs/<stack> runs/targets.json 30 --smoke` (background; the first one waits for the Rust build), then
`$HUNT report <results-dir>` and check the detail table: every target needs samples > 0 and zero lost/errors.
Fix `runs/targets.json` and repeat (about 1 min each time) until clean.

### 10. Full test (all candidates at the same moment, >= 5 min)

Before every test the probe source is synced to all instances over SSM (rebuilt only when it differs), so old winners and
new challengers run identical code. Feeds run in a second process on another core, so their traffic doesn't delay the RTT timestamps.

`$HUNT run runs/<stack> runs/targets.json <secs>` (background; takes secs + 1-2 min). The script waits for every build first,
then starts all probes together so they share the same time window. The last stdout line is the results directory.

### 11. Report

`$HUNT report <results-dir> --goal runs/goal.json [--keep N]`. It writes `report.md` and `keep.json` there. Show the user the
"Ranking by goal" table, the per-target tables (each instance's **fastest endpoint IP** with TCP handshake RTT / TLS / WS upgrade / req/resp RTT),
the market-data lag table, the per-AZ line and the recommendation, which lists every endpoint IP of each winner, fastest first.
The report also has a "Test environment and method" section (collected automatically on every run: OS, kernel, NIC driver,
sysctls, CPU, EC2 attributes, TLS version, no kernel bypass, no OS tuning, timestamp definitions). Tell the user to hand it to
anyone who wants to reproduce or compare the numbers, since results only line up when these match.
Then add 2-4 observations, e.g.:

- the p50 gap between the best and the median candidate (small = placement barely matters in that AZ, the AZ is what counts);
- which AZ is clearly closest, which is likely where the exchange gateway sits;
- candidates with good p50 but bad p99;
- conflicts between legs, and endpoints behind a CDN (see `references/exchanges.md`), where results matter less.

### 12. Recycle the losers (automatic, already confirmed in step 7)

`$HUNT prune <results-dir>`. It rebuilds the stack with only the kept candidates and creates a CloudFormation change set.
It executes the change set only if every change is a removal of a losing instance, its CPG, or the subnet of an AZ with no
winner left; anything else aborts with the offending changes listed, and then you ask the user. With nothing kept it deletes
the whole stack. Report what was kept, what was terminated, and the ongoing hourly cost.

### 12b. More rounds (when the user asked for them)

Each further round: `$HUNT round runs/<stack> <challengers-per-az>` adds fresh candidates in the AZs that still have a winner
(CloudFormation change set; it refuses anything but added instances and CPGs, so the winners are never touched), then repeat
steps 10-12 with `report --keep <survivors this round>`. Tell the user the round number and who survived after each one.
The last round's survivors are the final winners; show how they ranked in every round (the earlier `results/` dirs).

### 13. Hand-off

Tell the user (the skill itself never launches production):

- Keep the winner running: it anchors the CPG. Reboot only. stop/start or changing the instance type moves it to another host.
- Launch production into the winning CPG from **their own subnet in the same AZ** (the CPG is a regional resource, so any VPC
  works): `aws ec2 run-instances --placement GroupName=<cpg> --subnet-id <their-subnet> --instance-type <type> ...`.
  Launch all of them in one request to reduce capacity errors. Don't use the hunting subnet: deleting the run removes its route table.
- Re-test new production instances with the same targets. Same network segment, but different hosts.
- Once production is verified, `$HUNT destroy runs/<stack> --retain` deletes the test winner and everything else, but leaves
  any CPG that production instances use. Without production in the CPG, `$HUNT destroy runs/<stack>` removes everything.
  Always confirm before destroying.
- Placement is only "best for now": re-hunt periodically. `$HUNT list` shows the hunting stacks in a region.

## FAQ

- **OS tuning, hyper-threading off, turbo?** Not for test instances (see step 5). Only core pinning, which is free.
- **Atomic clock / PTP / time sync?** Not needed. RTT subtracts two readings of the same machine's monotonic clock; time sync
  only slews the frequency (well under 0.5 us on a 1 ms RTT). Clock sync matters only for one-way latency
  (exchange timestamp minus local time), which this skill deliberately doesn't use.
- **What exactly is timed?** The send stamp is taken after the request string is built, right before the socket write;
  the receive stamp as soon as the WebSocket frame arrives, before matching, with no JSON parsing. TLS and framing are
  included (a few us, the same on every instance).

## Troubleshooting

- SSM never online: VPC DNS support, or the hunting route table not pointing to the IGW.
- Build failed: `hunt.py` prints the tail of `/var/log/cloud-init-output.log` (usually no access to crates.io / rustup).
- A target stays at 0 samples: `/var/log/hunt.log` on the instance (`aws ssm start-session --target <id>`). Usual causes are a
  wrong URL/port/match, geo-blocking, a missing allowlist, or a missing private route.
- Results truncated: SSM returns 24,000 characters, about 100 rows (instances x exchange IPs). Split targets across runs.
