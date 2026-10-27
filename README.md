# aws-ec2-hunting-skill

A Claude Code skill that hunts for the EC2 placement with the lowest WebSocket latency to crypto exchanges.

By default it launches test instances across 7 partitions in a partition placement group per AZ. Each partition has
distinct rack sets. Every further round creates a new placement group with 7 fresh rack sets per AZ. It then measures
TCP handshake and WebSocket
request/response RTT from every instance to every IP of every exchange endpoint at the same time, for at least
5 minutes, and ranks the instances against your goal (for example "OKX order leg first, Binance market data second").
At the end it keeps the winning **instance** and terminates the rest. Keep that instance running; `sudo reboot` is fine,
but an OS-level shutdown, halt, or poweroff terminates the instance and its root volume. Stop/start can move it to
another host. Another instance in the same partition is not guaranteed to be as fast: re-measure it.
Use `--placement cluster` to give each candidate its own cluster placement group (CPG); in that mode the winning CPG
can host production instances in the same network segment.

## Install

```bash
git clone <this repo> ~/aws-ec2-hunting-skill
ln -s ~/aws-ec2-hunting-skill ~/.claude/skills/aws-ec2-hunting
```

Then ask Claude Code something like "run an EC2 hunt to Binance and OKX in Tokyo". The skill asks for the AWS profile,
AZ IDs, exchanges, endpoints, goal and VPC. It runs permission and network checks and shows the cost before it creates anything.

Requirements: AWS CLI v2, Python 3.9+, Node.js 18+ (CDK CLI runs via `npx aws-cdk@2`). Rust is optional, for local probe testing.
No `cdk bootstrap` is needed.

## Layout

```
SKILL.md                 workflow Claude follows
references/exchanges.md  how to pick and verify a measurement method per exchange
targets.example.json     verified exchange targets
scripts/hunt.py          perms, preflight, deploy, run, report, prune, destroy, list
infra/app.py             CDK app: one stack per run (subnets, route table, SG, IAM, launch templates, placement groups, instances)
probe/                   Rust WebSocket RTT probe, synced and built on instances by hunt.py run
runs/                    per-run config, synthesized templates and results (git-ignored)
```

## Manual use

Export `AWS_PROFILE` and `AWS_REGION` first.

```bash
HUNT="python3 scripts/hunt.py"
mkdir -p runs && cp targets.example.json runs/targets.json      # keep the targets you need
$HUNT perms
$HUNT preflight vpc-xxxx m8azn.large 7 apne1-az1 apne1-az4      # partition is the default
                                                                # add --placement cluster or --ami to override defaults
$HUNT deploy runs/<stack>
$HUNT run runs/<stack> runs/targets.json 30 --smoke
$HUNT run runs/<stack> runs/targets.json 600                   # prints the results directory
$HUNT report <results-dir> --goal runs/goal.json --keep 1       # partition: keep the fastest; goal format in SKILL.md
$HUNT prune <results-dir>                                      # keep the winners, terminate the rest
$HUNT round runs/<stack> 7                                     # partition: 7 fresh challengers per AZ in a new group
$HUNT run runs/<stack> runs/targets.json 600                   # test incumbents and challengers together
$HUNT report <new-results-dir> --goal runs/goal.json --keep 1
$HUNT prune <new-results-dir>                                  # keep the fastest instance and its group
$HUNT destroy runs/<stack> [--retain]                          # when done
$HUNT selftest                                                 # ranking and prune-safety checks
```

In partition mode, candidate index `i` uses group `i // 7` and partition `i % 7 + 1`. Every `round` adds exactly
7 candidates per surviving AZ, one per partition in a new group; it also tests the incumbent from its older group.
The inline CloudFormation template must hold both groups, so preflight checks the next round after `--keep 1`
overall (about 8 KB per group in the winner's AZ). With the current template, 3 AZs × 7 initial candidates fit;
a 4 AZ × 6 run exceeds the 51,200-byte limit and preflight reports a maximum of 5 per AZ. Keeping a winner in
every AZ can make the next round too large; preflight warns to keep 1 overall or split AZs into separate runs. Cluster mode keeps the
`round` count as a per-AZ choice. The probe source is synced over SSM and built by `hunt.py run`;
partition-mode user data only bootstraps the toolchain.

## How it measures

- The probe opens one TLS WebSocket per (target, exchange IP), with TCP_NODELAY, and connects to the IP directly while keeping
  the hostname for SNI. It has one request in flight per connection, matches replies by id, and staggers send times across connections.
- Every report ends its tables with a "Test environment and method" section (OS, kernel, NIC, sysctls, CPU, EC2 attributes,
  TLS version, kernel bypass: none, OS tuning: none, timestamp definitions), collected on the instances at test time.
- Per endpoint IP the report also shows the TCP handshake (min/p50 of 5), the TLS handshake and the WebSocket upgrade, and for
  `feed` targets the live market-data lag (local clock minus the exchange's event timestamp, ms resolution, relative use only).
- The send stamp is taken after the request is built, the receive stamp when the frame arrives (before matching).
  Both use a monotonic clock, so time sync doesn't matter.
- The hunting subnets route straight to the internet gateway. Behind a NAT gateway every candidate would share the NAT's path.
- There is no OS tuning: all candidates run the same image and script at the same moment, so OS noise cancels out.
  The probe is pinned to one core.
