# aws-ec2-hunting-skill

A Claude Code skill that hunts for the EC2 placement with the lowest WebSocket latency to crypto exchanges.

It launches test instances in the AZ IDs you choose, each in its own cluster placement group. It then measures
request/response RTT from every instance to every IP of every exchange endpoint at the same time, for at least
5 minutes, and ranks the instances against your goal (for example "OKX order leg first, Binance market data second").
At the end it keeps the winner and its CPG and terminates the rest. Production instances you launch into the winning CPG
later land in the same network segment.

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
infra/app.py             CDK app: one stack per run (subnets, route table, SG, IAM, launch template, CPGs, instances)
probe/                   Rust WebSocket RTT probe, built on the instances from user data
runs/                    per-run config, synthesized templates and results (git-ignored)
```

## Manual use

Export `AWS_PROFILE` and `AWS_REGION` first.

```bash
HUNT="python3 scripts/hunt.py"
mkdir -p runs && cp targets.example.json runs/targets.json      # keep the targets you need
$HUNT perms
$HUNT preflight vpc-xxxx m8azn.large 7 apne1-az1 apne1-az4      # prints checks, creates runs/<stack>/
                                                                # add --ami ami-xxx or /ssm/param to override AL2023
$HUNT deploy runs/<stack>
$HUNT run runs/<stack> runs/targets.json 30 --smoke
$HUNT run runs/<stack> runs/targets.json 600                   # prints the results directory
$HUNT report <results-dir> --goal runs/goal.json [--keep N]    # goal format: see SKILL.md step 3
$HUNT prune <results-dir>                                      # keep the winners, terminate the rest
$HUNT round runs/<stack> 5                                     # next round: 5 fresh challengers per AZ next to the winners
$HUNT destroy runs/<stack> [--retain]                          # when done
$HUNT selftest                                                 # ranking and prune-safety checks
```

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
