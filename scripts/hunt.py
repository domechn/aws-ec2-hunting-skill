#!/usr/bin/env python3
"""EC2 hunting helper. Export AWS_PROFILE and AWS_REGION for every command.

A run is one CloudFormation stack (synthesized by infra/app.py) plus a local directory runs/<stack>/.

  hunt.py perms                                       can this identity run the whole flow?
  hunt.py preflight VPC TYPE PER_AZ AZ_ID... [--placement partition|cluster] [--secs N] [--ami ami-xxx|/ssm/param] [--route CIDR=pcx-|tgw-id]...
                                                      network/capacity/quota/price checks, creates runs/<stack>/
  hunt.py deploy RUN                                  synth + deploy the stack (no cdk bootstrap needed)
  hunt.py run RUN TARGETS SECS [--smoke]              probe every candidate at the same moment, save results
  hunt.py report RESULTS [--goal GOAL] [--keep N]     rank by goal, write report.md and keep.json
  hunt.py prune RESULTS                               terminate every candidate not in keep.json (change set is checked)
  hunt.py round RUN PER_AZ                            partition: 7 challengers per AZ in a new group; cluster: PER_AZ
  hunt.py destroy RUN [--retain]                      delete the whole stack, kept winners included
  hunt.py list                                        hunting stacks in this region
  hunt.py selftest
"""
import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
VENV = ROOT / "infra" / ".venv"
STACK_PREFIX = "ec2-hunt-"
BIN = "/opt/hunt/probe/target/release/probe"
MIN_SECS = 300
SMOKE_SECS = 30
SSM_STDOUT_LIMIT = 24000  # get-command-invocation truncates StandardOutputContent here
TEMPLATE_LIMIT = 51200  # inline template body limit; above it CDK would need a bootstrap bucket
PARTITIONS = 7
IPV4_USD_PER_HOUR = 0.005  # public IPv4 address charge
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-{arch}"

REQUIRED_ACTIONS = [f"cloudformation:{a}" for a in (
    "CreateChangeSet DescribeChangeSet ExecuteChangeSet DeleteChangeSet DescribeStacks DescribeStackEvents "
    "GetTemplate DescribeStackResources DeleteStack").split()] + [f"ec2:{a}" for a in (
    "DescribeAvailabilityZones DescribeVpcs DescribeVpcAttribute DescribeSubnets DescribeRouteTables "
    "DescribeInternetGateways DescribeNetworkAcls DescribeSecurityGroups DescribePlacementGroups DescribeInstances "
    "DescribeInstanceTypes DescribeImages DescribeNetworkInterfaces DescribeInstanceTypeOfferings DescribeLaunchTemplates DescribeLaunchTemplateVersions "
    "CreateTags CreatePlacementGroup DeletePlacementGroup CreateSubnet DeleteSubnet ModifySubnetAttribute "
    "CreateRouteTable DeleteRouteTable CreateRoute DeleteRoute AssociateRouteTable DisassociateRouteTable "
    "CreateInternetGateway AttachInternetGateway DetachInternetGateway DeleteInternetGateway CreateSecurityGroup "
    "DeleteSecurityGroup AuthorizeSecurityGroupEgress RevokeSecurityGroupEgress CreateLaunchTemplate "
    "DeleteLaunchTemplate RunInstances TerminateInstances").split()] + [f"iam:{a}" for a in (
    "GetRole CreateRole DeleteRole AttachRolePolicy DetachRolePolicy CreateInstanceProfile DeleteInstanceProfile "
    "GetInstanceProfile AddRoleToInstanceProfile RemoveRoleFromInstanceProfile PassRole").split()] + \
    [f"ssm:{a}" for a in "GetParameter SendCommand ListCommandInvocations GetCommandInvocation "
                         "DescribeInstanceInformation".split()]
OPTIONAL_ACTIONS = ["servicequotas:GetServiceQuota", "pricing:GetProducts"]
# What prune is allowed to remove (anything else in the change set aborts it).
PRUNABLE = {"AWS::EC2::Instance", "AWS::EC2::PlacementGroup", "AWS::EC2::LaunchTemplate", "AWS::EC2::Subnet", "AWS::EC2::SubnetRouteTableAssociation"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def sh(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def aws(*args):
    out = sh("aws", *args, "--output", "json")
    return json.loads(out) if out.strip() else None

    return (getattr(e, "stderr", None) or str(e)).strip().splitlines()[-1]
def err_line(e):
    return (e.stderr or str(e)).strip().splitlines()[-1]


def alnum(s):  # same logical-id scheme as infra/app.py
    return "".join(ch for ch in s if ch.isalnum())


def load_cfg(run):
    return json.loads((Path(run) / "config.json").read_text())


def candidates(stack):
    """{key: {...}} for the stack's running candidates, found by the tags CloudFormation and app.py set."""
    found = aws("ec2", "describe-instances", "--filters", f"Name=tag:aws:cloudformation:stack-name,Values={stack}",
                "Name=instance-state-name,Values=pending,running", "--query", "Reservations[].Instances[]")
    out = {}
    for i in found:
        key = next(t["Value"] for t in i["Tags"] if t["Key"] == "hunt:key")
        out[key] = {"instance_id": i["InstanceId"], "public_ip": i.get("PublicIpAddress"), "az_id": key.rsplit("-", 1)[0],
                    "placement_group": i["Placement"].get("GroupName"), "partition": i["Placement"].get("PartitionNumber"),
                    "subnet_id": i["SubnetId"]}
    return dict(sorted(out.items()))


# ---------------------------------------------------------------- perms

def perms():
    ident = aws("sts", "get-caller-identity")
    arn = ident["Arn"]
    print(f"Account {ident['Account']}, identity {arn}")
    if arn.endswith(":root"):
        print("WARN  root credentials: permissions are sufficient, but use an IAM role/user instead")
        return 0
    try:
        # Simulation needs the IAM role ARN (with its path), not the STS session ARN.
        src = aws("iam", "get-role", "--role-name", arn.split("/")[1])["Role"]["Arn"] \
            if ":assumed-role/" in arn else arn
        res = aws("iam", "simulate-principal-policy", "--policy-source-arn", src,
                  "--action-names", *REQUIRED_ACTIONS, *OPTIONAL_ACTIONS)["EvaluationResults"]
    except subprocess.CalledProcessError as e:
        print(f"WARN  could not simulate permissions ({err_line(e)}). Ask the user to confirm the identity "
              f"can perform: {' '.join(REQUIRED_ACTIONS)}")
        return 0
    denied = {r["EvalActionName"]: r["EvalDecision"] for r in res if r["EvalDecision"] != "allowed"}
    hard = [a for a in REQUIRED_ACTIONS if a in denied]
    soft = [a for a in OPTIONAL_ACTIONS if a in denied]
    if soft:
        print(f"WARN  optional actions denied (quota/price checks will be skipped): {' '.join(soft)}")
    if hard:
        print("FAIL  denied: " + " ".join(f"{a}({denied[a]})" for a in hard))
        print("      Policies scoped to specific resources can show up as implicitDeny here; confirm with the user.")
        return 1
    print(f"OK    all {len(REQUIRED_ACTIONS)} required actions allowed by identity policies "
          "(SCPs are covered by the RunInstances dry run in preflight)")
    return 0


# ---------------------------------------------------------------- preflight

def free_cidrs(vpc, subnets, az_ids):
    blocks = [ipaddress.ip_network(b["CidrBlock"]) for b in vpc["CidrBlockAssociationSet"]
              if b["CidrBlockState"]["State"] == "associated"]
    used = [ipaddress.ip_network(s["CidrBlock"]) for s in subnets]
    # Take from the top of the range, where teams rarely allocate.
    free = (n for b in blocks if b.prefixlen <= 27 for n in reversed(list(b.subnets(new_prefix=27)))
            if not any(n.overlaps(u) for u in used))
    try:
        return {az: str(next(free)) for az in az_ids}
    except StopIteration:
        return None


def standard_vcpus_in_use():
    # Approximation of usage of the "Standard (A, C, D, H, I, M, R, T, Z)" On-Demand vCPU quota.
    res = aws("ec2", "describe-instances", "--filters", "Name=instance-state-name,Values=pending,running",
              "--query", "Reservations[].Instances[].[InstanceType,CpuOptions.CoreCount,CpuOptions.ThreadsPerCore]")
    return sum(c * t for typ, c, t in res
               if typ[0] in "acdhimrtz" and not typ.startswith(("inf", "dl", "trn", "hpc", "u-")))


def on_demand_price(itype, region):
    filters = [f"Type=TERM_MATCH,Field={k},Value={v}" for k, v in {
        "instanceType": itype, "regionCode": region, "operatingSystem": "Linux", "tenancy": "Shared",
        "preInstalledSw": "NA", "capacitystatus": "Used", "licenseModel": "No License required"}.items()]
    items = aws("pricing", "get-products", "--region", "us-east-1", "--service-code", "AmazonEC2",
                "--filters", *filters)["PriceList"]
    term = next(iter(json.loads(items[0])["terms"]["OnDemand"].values()))
    return float(next(iter(term["priceDimensions"].values()))["pricePerUnit"]["USD"])


def preflight(vpc_id, itype, per_az, az_ids, secs, routes, ami_spec=None, placement="partition"):
    region = os.environ["AWS_REGION"]
    checks = []  # (level, message)
    add = lambda level, msg: checks.append((level, msg))

    vpc = aws("ec2", "describe-vpcs", "--vpc-ids", vpc_id)["Vpcs"][0]
    dns = aws("ec2", "describe-vpc-attribute", "--vpc-id", vpc_id,
              "--attribute", "enableDnsSupport")["EnableDnsSupport"]["Value"]
    add("OK" if dns else "FAIL", "VPC DNS resolution " +
        ("enabled" if dns else "disabled: SSM and exchange hostnames won't resolve"))

    igws = aws("ec2", "describe-internet-gateways",
               "--filters", f"Name=attachment.vpc-id,Values={vpc_id}")["InternetGateways"]
    igw_id = igws[0]["InternetGatewayId"] if igws else ""
    add("OK", f"IGW {igw_id} is attached and will be reused (never modified or deleted)" if igw_id else
        "VPC has no IGW: the stack will create and attach one (removed again on destroy)")

    rts = aws("ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={vpc_id}")["RouteTables"]
    edge = [rt["RouteTableId"] for rt in rts for a in rt.get("Associations", [])
            if igw_id and a.get("GatewayId") == igw_id]
    if edge:
        add("WARN", f"IGW has an ingress route table {edge}: return traffic passes a firewall/appliance first")
    else:
        add("OK", "no ingress routing on the IGW (return traffic doesn't detour through an appliance)")

    nacl = aws("ec2", "describe-network-acls", "--filters", f"Name=vpc-id,Values={vpc_id}",
               "Name=default,Values=true")["NetworkAcls"][0]["Entries"]

    def allow_all(egress):
        first = min((e for e in nacl if e["Egress"] == egress), key=lambda e: e["RuleNumber"])
        return first["RuleAction"] == "allow" and first["Protocol"] == "-1" and first.get("CidrBlock") == "0.0.0.0/0"
    if allow_all(True) and allow_all(False):
        add("OK", "default network ACL allows all traffic")
    else:
        add("WARN", "default network ACL has custom rules; the new subnets inherit it and may block exchange "
                    "traffic (the smoke test will show it)")

    subnets = aws("ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}")["Subnets"]
    az_subnets = free_cidrs(vpc, subnets, az_ids)
    if az_subnets:
        add("OK", "new /27 subnet per AZ, routed 0.0.0.0/0 -> IGW directly (no NAT): " +
            ", ".join(f"{a} {c}" for a, c in az_subnets.items()))
    else:
        add("FAIL", f"no free /27 left in {vpc_id}")
    for cidr, target in routes.items():
        add("OK", f"extra route {cidr} -> {target}")

    info = aws("ec2", "describe-instance-types", "--instance-types", itype)["InstanceTypes"][0]
    offered = {o["Location"] for o in aws("ec2", "describe-instance-type-offerings", "--location-type",
                                          "availability-zone-id", "--filters",
                                          f"Name=instance-type,Values={itype}")["InstanceTypeOfferings"]}
    missing = [a for a in az_ids if a not in offered]
    if missing:
        add("FAIL", f"{itype} is not offered in {missing}")
    else:
        add("OK", f"{itype} is offered in every chosen AZ")
    if placement == "cluster" and itype.startswith("t") and itype[1].isdigit():
        add("FAIL", "T family instances can't join a cluster placement group")
    if placement == "partition":
        add("OK", "partition placement groups of 7 rack sets; candidate i -> group i//7, partition i%7+1")

    count = per_az * len(az_ids)
    need = info["VCpuInfo"]["DefaultVCpus"] * count
    try:
        quota = aws("service-quotas", "get-service-quota", "--service-code", "ec2",
                    "--quota-code", "L-1216C47A")["Quota"]["Value"]
        used = standard_vcpus_in_use()
        add("OK" if used + need <= quota else "FAIL",
            f"On-Demand standard vCPU quota {quota:.0f}, in use ~{used}, this run needs {need}")
    except subprocess.CalledProcessError as e:
        add("WARN", f"could not read the vCPU quota ({err_line(e)}); this run needs {need} vCPUs")

    arch = "arm64" if "arm64" in info["ProcessorInfo"]["SupportedArchitectures"] else "x86_64"
    ami = ami_spec or AMI_PARAM.format(arch=arch)  # no --ami: latest Amazon Linux 2023
    if ami.startswith("/"):  # SSM public parameter, e.g. the Ubuntu or AL2 one
        ami = aws("ssm", "get-parameter", "--name", ami)["Parameter"]["Value"]
    try:
        img = aws("ec2", "describe-images", "--image-ids", ami)["Images"][0]
        label = img.get("Name", ami)
        if img["Architecture"] != arch:
            add("FAIL", f"AMI {ami} is {img['Architecture']} but {itype} needs {arch}")
        elif img["State"] != "available":
            add("FAIL", f"AMI {ami} is {img['State']}")
        elif not re.search(r"al2023|amzn2|ubuntu", label, re.I):
            add("WARN", f"AMI {ami} ({label}) is not Amazon Linux or Ubuntu: it needs cloud-init and the SSM agent, "
                        "or the instances never come online")
    except (subprocess.CalledProcessError, IndexError) as e:
        label = ami
        add("FAIL", f"AMI {ami} not found or not visible in {region}: {err_line(e) if isinstance(e, subprocess.CalledProcessError) else 'no such image'}")
    if subnets:
        try:
            sh("aws", "ec2", "run-instances", "--dry-run", "--image-id", ami, "--instance-type", itype,
               "--subnet-id", subnets[0]["SubnetId"])
        except subprocess.CalledProcessError as e:
            if "DryRunOperation" in e.stderr:
                add("OK", f"RunInstances dry run allowed (AMI {ami}, {label})")
            elif "UnauthorizedOperation" in e.stderr:
                add("FAIL", f"RunInstances dry run denied (IAM or SCP): {err_line(e)}")
            else:
                add("WARN", f"RunInstances dry run inconclusive: {err_line(e)}")
    else:
        add("WARN", "VPC has no subnet to dry-run RunInstances against; skipped")

    hours = 0.25 + secs / 3600  # boot + build + smoke + teardown, plus the test itself
    try:
        price = on_demand_price(itype, region)
        cost = {"usd_per_instance_hour": price, "hours": round(hours, 2),
                "estimated_run_usd": round(count * (price + IPV4_USD_PER_HOUR) * hours, 2),
                "kept_winner_usd_per_hour": round(price + IPV4_USD_PER_HOUR, 4)}
    except (subprocess.CalledProcessError, IndexError, KeyError) as e:
        cost = {"error": f"price lookup failed: {e}", "hours": round(hours, 2)}

    stack = STACK_PREFIX + time.strftime("%Y%m%d-%H%M%S")
    cfg = {"stack": stack, "region": region, "vpc_id": vpc_id, "igw_id": igw_id, "az_subnets": az_subnets,
           "instance_type": itype, "instances_per_az": per_az, "ami": ami, "extra_routes": routes, "keep": [],
           "placement": placement}
    if az_subnets:
        try:
            size, round_size, maximum = template_size_and_max(cfg)
            if max(size, round_size or 0) <= TEMPLATE_LIMIT:
                detail = f"; next keep-1 partition round {round_size} bytes" if round_size else ""
                add("OK", f"template {size} bytes{detail} (inline limit {TEMPLATE_LIMIT})")
                if round_size and len(az_ids) > 1:
                    all_az_round_size = offline_template_size(round_template_cfg(cfg, keep_per_az=True))
                    if all_az_round_size > TEMPLATE_LIMIT:
                        add("WARN", f"keeping a winner in every AZ makes the next round {all_az_round_size} bytes, "
                            f"over the {TEMPLATE_LIMIT}-byte inline limit; keep 1 overall or split AZs into separate runs")
            else:
                detail = f"; next keep-1 partition round {round_size} bytes" if round_size else ""
                label = ("max initial candidates per AZ that still allow a keep-1 round" if round_size else
                         "max candidates per AZ that fit")
                add("FAIL", f"template {size} bytes{detail} exceeds the {TEMPLATE_LIMIT}-byte inline limit; "
                    f"{label}: "
                    f"{maximum if maximum is not None else 'none for these AZs (split into separate runs)'}")
        except (subprocess.CalledProcessError, OSError) as e:
            add("FAIL", f"could not synthesize template: {err_line(e)}")

    for level, msg in checks:
        print(f"{level:5} {msg}")
    print("COST  " + json.dumps(cost))
    if any(level == "FAIL" for level, _ in checks):
        print("No run created: fix the FAIL items first.")
        return 1
    run = RUNS / stack
    run.mkdir(parents=True)
    (run / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"RUN   {run}  ({count} x {itype}, AMI {ami})")
    return 0


# ---------------------------------------------------------------- deploy / destroy

def ensure_cdk_venv():
    if not (VENV / "bin" / "python").exists():
        log("creating infra/.venv with aws-cdk-lib (first run only)")
        sh(sys.executable, "-m", "venv", str(VENV))
        sh(str(VENV / "bin" / "pip"), "install", "-q", "-r", str(ROOT / "infra" / "requirements.txt"))


def offline_template_size(cfg):
    ensure_cdk_venv()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        config = tmp / "config.json"
        config.write_text(json.dumps(cfg))
        out = tmp / "cdk.out"
        env = {**os.environ, "JSII_RUNTIME_PACKAGE_CACHE": "disabled",
               "CDK_CONTEXT_JSON": json.dumps({"config": str(config), "aws:cdk:enable-path-metadata": True}),
               "CDK_OUTDIR": str(out)}
        subprocess.run([str(VENV / "bin" / "python"), str(ROOT / "infra" / "app.py")], check=True, cwd=tmp,
                       env=env, capture_output=True, text=True)
        return (out / f"{cfg['stack']}.template.json").stat().st_size


def round_template_cfg(candidate, keep_per_az=False):
    start = ((candidate["instances_per_az"] + PARTITIONS - 1) // PARTITIONS) * PARTITIONS
    azs = list(candidate["az_subnets"])
    if not keep_per_az:
        azs = azs[:1]
    return {**candidate, "az_subnets": {az: candidate["az_subnets"][az] for az in azs},
            "keep": [f"{az}-0" for az in azs],
            "new": [f"{az}-{n}" for az in azs for n in range(start, start + PARTITIONS)]}


def template_size_and_max(cfg):
    size = offline_template_size(cfg)
    round_size = offline_template_size(round_template_cfg(cfg)) if cfg.get("placement", "cluster") == "partition" else None
    if max(size, round_size or 0) <= TEMPLATE_LIMIT:
        return size, round_size, None
    def fits(count):
        candidate = {**cfg, "instances_per_az": count}
        return (offline_template_size(candidate) <= TEMPLATE_LIMIT and
                (round_size is None or offline_template_size(round_template_cfg(candidate)) <= TEMPLATE_LIMIT))
    if cfg["instances_per_az"] <= 1 or not fits(1):
        return size, round_size, None
    low, high = 1, cfg["instances_per_az"] - 1
    while low < high:
        middle = (low + high + 1) // 2
        if fits(middle):
            low = middle
        else:
            high = middle - 1
    return size, round_size, low


def cdk(*args):
    ensure_cdk_venv()
    subprocess.run(["npx", "--yes", "aws-cdk@2", *args, "--no-notices"], check=True, cwd=ROOT,
                   env={**os.environ, "CDK_DISABLE_CLI_TELEMETRY": "true", "JSII_RUNTIME_PACKAGE_CACHE": "disabled"})


def pin_user_data(run, cfg, template):
    """Copy the launch template's user data from a synthesized template into config.json, once, so that later
    synths (prune, round) can never change the launch template and make CloudFormation replace the running winners."""
    if "user_data" in cfg or not template.exists():
        return cfg
    lt = next(r for r in json.loads(template.read_text())["Resources"].values() if r["Type"] == "AWS::EC2::LaunchTemplate")
    cfg["user_data"] = lt["Properties"]["LaunchTemplateData"]["UserData"]
    (Path(run) / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    return cfg


def synth(run):
    run = Path(run)
    cfg = load_cfg(run)
    template = run / "cdk.out" / f"{cfg['stack']}.template.json"
    cfg = pin_user_data(run, cfg, template)  # from the previous synth, which is what the stack was deployed with
    cdk("synth", "--quiet", "--app", f"{VENV}/bin/python {ROOT}/infra/app.py", "-c", f"config={run / 'config.json'}",
        "--output", str(run / "cdk.out"))
    cfg = pin_user_data(run, cfg, template)
    size = len(template.read_bytes())
    if size > TEMPLATE_LIMIT:
        advice = ("keep 1 overall or split AZs into separate runs" if cfg.get("placement", "cluster") == "partition"
                  else "use fewer candidates per AZ or split the AZs into separate runs")
        sys.exit(f"template is {size} bytes, over the {TEMPLATE_LIMIT}-byte inline limit: {advice}")
    return cfg, template


def deploy(run):
    cfg, _ = synth(run)
    cdk("deploy", cfg["stack"], "--app", str(Path(run) / "cdk.out"), "--require-approval", "never")
    print(json.dumps(candidates(cfg["stack"]), indent=2))


def foreign_instances(stack, name, values):
    """Instances matching an EC2 filter that this stack didn't launch (e.g. production next to a kept winner)."""
    if not values:
        return []
    found = aws("ec2", "describe-instances", "--filters", f"Name={name},Values={','.join(values)}",
                "Name=instance-state-name,Values=pending,running,stopping,stopped", "--query", "Reservations[].Instances[]")
    return [i for i in found if {"Key": "aws:cloudformation:stack-name", "Value": stack} not in i.get("Tags", [])]


def destroy(run, retain=False):
    stack = load_cfg(run)["stack"]
    res = aws("cloudformation", "describe-stack-resources", "--stack-name", stack)["StackResources"]
    phys = lambda typ: {r["PhysicalResourceId"]: r["LogicalResourceId"] for r in res if r["ResourceType"] == typ}
    in_subnets = foreign_instances(stack, "subnet-id", list(phys("AWS::EC2::Subnet")))
    if in_subnets:
        sys.exit("refusing to delete: these instances aren't part of the hunt but sit in its subnets, and deleting "
                 "the stack removes their route table: " + ", ".join(i["InstanceId"] for i in in_subnets))
    groups = phys("AWS::EC2::PlacementGroup")
    in_use = {i["Placement"]["GroupName"] for i in foreign_instances(stack, "placement-group-name", list(groups))}
    if in_use and not retain:
        sys.exit(f"placement groups {sorted(in_use)} hold instances outside the hunt (production?). Rerun with "
                 "--retain to delete everything else and leave those groups in the account.")
    aws("cloudformation", "delete-stack", "--stack-name", stack)
    log(f"deleting {stack}")
    try:
        sh("aws", "cloudformation", "wait", "stack-delete-complete", "--stack-name", stack)
    except subprocess.CalledProcessError:
        if not in_use:
            raise
        # CloudFormation only accepts --retain-resources once the first delete has failed on them.
        aws("cloudformation", "delete-stack", "--stack-name", stack, "--retain-resources", *(groups[g] for g in in_use))
        sh("aws", "cloudformation", "wait", "stack-delete-complete", "--stack-name", stack)
        print(f"kept placement groups {sorted(in_use)} outside any stack")
    print(f"{stack} deleted")


def list_runs():
    stacks = aws("cloudformation", "describe-stacks")["Stacks"]
    for s in stacks:
        if s["StackName"].startswith(STACK_PREFIX):
            cands = candidates(s["StackName"])
            print(f"{s['StackName']}  {s['StackStatus']}  running candidates: "
                  + (", ".join(f"{k} {c['instance_id']} {pg(c)}" for k, c in cands.items()) or "none"))


# ---------------------------------------------------------------- run

def wait_online(ids):
    for _ in range(60):
        info = aws("ssm", "describe-instance-information",
                   "--filters", f"Key=InstanceIds,Values={','.join(ids)}")["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i["PingStatus"] == "Online"}
        log(f"SSM online {len(online)}/{len(ids)}")
        if online >= set(ids):
            return
        time.sleep(15)
    sys.exit("instances never came online in SSM: check the instance profile and the IGW route")


def ssm(ids, commands, timeout, what):
    """Run commands on all ids, wait, return {instance_id: stdout} for the ones that succeeded."""
    params = json.dumps({"commands": commands, "executionTimeout": [str(timeout)]})
    cid = aws("ssm", "send-command", "--instance-ids", *ids, "--document-name", "AWS-RunShellScript",
              "--comment", f"aws-ec2-hunting {what}", "--parameters", params)["Command"]["CommandId"]
    log(f"{what}: command {cid} sent to {len(ids)} instance(s)")
    deadline = time.time() + timeout + 300
    while True:
        time.sleep(15)
        inv = aws("ssm", "list-command-invocations", "--command-id", cid)["CommandInvocations"]
        done = [i for i in inv if i["Status"] not in ("Pending", "InProgress", "Delayed", "Cancelling")]
        log(f"{what}: {len(done)}/{len(ids)} finished")
        if len(done) == len(ids):
            break
        if time.time() > deadline:
            sys.exit(f"{what}: timed out waiting for {cid}")
    outs = {}
    for iid in ids:
        r = aws("ssm", "get-command-invocation", "--command-id", cid, "--instance-id", iid)
        if r["Status"] == "Success":
            outs[iid] = r["StandardOutputContent"]
        else:
            log(f"{what}: {iid} {r['Status']}\n{r['StandardOutputContent']}\n{r['StandardErrorContent']}")
    return outs


PROBE_FILES = ["Cargo.toml", "Cargo.lock", "src/main.rs"]


def probe_sync_commands():
    """SSM commands that bring /opt/hunt/probe to this checkout's source and rebuild it, or do nothing if it already
    matches. Instances keep the probe they were launched with (the launch template is pinned), so older winners
    and fresh challengers are made identical here before every test."""
    files = {f: (ROOT / "probe" / f).read_bytes() for f in PROBE_FILES}
    digest = hashlib.sha256(b"".join(files.values())).hexdigest()
    cmds = [f"cd /opt/hunt/probe && [ \"$(cat {' '.join(PROBE_FILES)} | sha256sum | cut -d' ' -f1)\" = {digest} ] "
            f"&& test -x {BIN} "
            "&& { echo in-sync; exit 0; }"]
    for f, data in files.items():  # chunked: SSM limits the size of each command
        b64 = base64.b64encode(gzip.compress(data, mtime=0)).decode()
        cmds += [": > /tmp/sync.b64"] + [f"echo -n '{b64[i:i + 3000]}' >> /tmp/sync.b64" for i in range(0, len(b64), 3000)]
        cmds.append(f"base64 -d /tmp/sync.b64 | gunzip > /opt/hunt/probe/{f}")
    cmds.append("bash -o pipefail -c 'export HOME=/root RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust; "
                f"rm -f {BIN} && /opt/rust/bin/cargo build --release --manifest-path /opt/hunt/probe/Cargo.toml 2>&1 | tail -5 "
                "&& "
                f"test -x {BIN} && echo rebuilt'")
    return cmds


def collect_env(ids, cands):
    """What the numbers were measured on: EC2 attributes from the API plus OS/kernel/NIC/tuning read on each instance."""
    byid = {c["instance_id"]: k for k, c in cands.items()}
    nis = aws("ec2", "describe-network-interfaces", "--filters", f"Name=attachment.instance-id,Values={','.join(ids)}")
    srd = {n["Attachment"]["InstanceId"]: (n["Attachment"].get("EnaSrdSpecification") or {}).get("EnaSrdEnabled", False)
           for n in nis["NetworkInterfaces"] if n.get("Attachment", {}).get("InstanceId")}
    ec2 = {}
    for i in aws("ec2", "describe-instances", "--instance-ids", *ids, "--query", "Reservations[].Instances[]"):
        iid, cpu = i["InstanceId"], i.get("CpuOptions", {})
        ec2[iid] = {"instance_type": i["InstanceType"], "ami": i["ImageId"], "az_id": cands[byid[iid]]["az_id"],
                    "placement": (f"partition placement group {i['Placement'].get('GroupName')}"
                                  if i["Placement"].get("PartitionNumber") else "cluster placement group, one instance per group")
                                 + f", tenancy {i['Placement'].get('Tenancy')}",
                    "cpu": f"{cpu.get('CoreCount')} cores x {cpu.get('ThreadsPerCore')} threads",
                    "ena_support": i.get("EnaSupport"), "ena_express": "enabled" if srd.get(iid) else "off",
                    "ebs_optimized": i.get("EbsOptimized"), "imds_tokens": i.get("MetadataOptions", {}).get("HttpTokens"),
                    "detailed_monitoring": i["Monitoring"]["State"]}
    script = base64.b64encode((ROOT / "scripts" / "env_probe.py").read_bytes()).decode()
    outs = ssm(ids, [f"echo {script} | base64 -d > /tmp/env_probe.py", "python3 /tmp/env_probe.py"], 300, "environment")
    return {"ec2": ec2, "hosts": {iid: json.loads(out.strip().splitlines()[-1]) for iid, out in outs.items()}}


def run_probe(run, targets, secs, smoke):
    if smoke:
        secs = SMOKE_SECS
    elif secs < MIN_SECS:
        sys.exit(f"duration must be >= {MIN_SECS}s (got {secs})")
    cands = candidates(load_cfg(run)["stack"])
    ids = [c["instance_id"] for c in cands.values()][: 1 if smoke else None]
    if not ids:
        sys.exit("no running candidates in this run")
    wait_online(ids)
    # Wait for the build everywhere first, so the real test starts at the same moment on every instance.
    ready = ssm(ids, [f"cloud-init status --wait >/dev/null; test -x {BIN} || test -x /opt/rust/bin/cargo || "
                      "{ tail -40 /var/log/cloud-init-output.log; exit 1; }"], 1800, "build")
    if not ready:
        sys.exit("no instance finished building the probe")
    synced = ssm(list(ready), probe_sync_commands(), 1800, "probe sync")
    ready = {i: o for i, o in ready.items() if i in synced}
    if not ready:
        sys.exit("probe sync failed everywhere")
    env = collect_env(list(ready), cands)
    all_targets = json.loads(Path(targets).read_text())
    feeds = [t for t in all_targets if t.get("ts_key")]
    enc = lambda v: base64.b64encode(json.dumps(v).encode()).decode()
    # Pin the RTT probe to CPU 1 (CPU 0 keeps most IRQs); fall back to 0 on single-vCPU types.
    rtt_cpu = "$(( $(nproc) > 1 ? 1 : 0 ))"
    if feeds:
        # Live feeds push hundreds of messages a second: a second process on another core keeps them from
        # delaying the RTT probe's receive timestamps.
        cmds = [f"echo {enc([t for t in all_targets if not t.get('ts_key')])} | base64 -d > /opt/hunt/targets.json",
                f"echo {enc(feeds)} | base64 -d > /opt/hunt/feeds.json",
                f"taskset -c {rtt_cpu} {BIN} /opt/hunt/targets.json {secs} 2>/var/log/hunt.log >/tmp/rtt.out & "
                f"taskset -c 0 {BIN} /opt/hunt/feeds.json {secs} 2>/var/log/hunt-feed.log >/tmp/feed.out & wait",
                "python3 -c \"import json; print(json.dumps(json.load(open('/tmp/rtt.out')) + json.load(open('/tmp/feed.out'))))\""]
    else:
        cmds = [f"echo {enc(all_targets)} | base64 -d > /opt/hunt/targets.json",
                f"taskset -c {rtt_cpu} {BIN} /opt/hunt/targets.json {secs} 2>/var/log/hunt.log"]
    outs = ssm(list(ready), cmds, secs + 600, "smoke" if smoke else "probe")

    out_dir = Path(run) / "results" / (time.strftime("%Y%m%d-%H%M%S") + ("-smoke" if smoke else ""))
    out_dir.mkdir(parents=True)
    (out_dir / "candidates.json").write_text(json.dumps(cands, indent=2))
    (out_dir / "targets.json").write_bytes(Path(targets).read_bytes())
    (out_dir / "meta.json").write_text(json.dumps({"duration_secs": secs, "smoke": smoke}))
    (out_dir / "env.json").write_text(json.dumps(env, indent=1))
    for iid, out in outs.items():
        if len(out) >= SSM_STDOUT_LIMIT:
            log(f"{iid}: output hit the SSM {SSM_STDOUT_LIMIT}-char limit, results truncated; test fewer targets")
            continue
        (out_dir / f"{iid}.json").write_text(json.dumps(json.loads(out), indent=1))
    log(f"saved {len(outs)} result file(s)")
    print(out_dir)


# ---------------------------------------------------------------- report

def table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return "\n".join(lines + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def rank(best, keys, goal):
    """Order eligible candidates by the goal's tiers.

    Each tier scores a candidate as the mean over its targets of (value / best value among candidates).
    Every tier but the last is a filter: only candidates within tolerance_pct of the tier's best survive.
    The last tier picks the winner among the survivors; repeat on the remainder for the full order.
    """
    metric = goal.get("metric", "p50")
    tiers = goal["tiers"]
    names = [t for tier in tiers for t in tier["targets"]]
    val = lambda c, t: best[t][c]["stats_us"][metric]
    complete = {k for k in keys if all(k in best[t] for t in names)}
    floor = {t: max(1, min(val(c, t) for c in complete)) for t in names} if complete else {}
    score = lambda c, tier: statistics.mean(val(c, t) / floor[t] for t in tier["targets"])
    reasons = {k: "no data for every goal target" for k in set(keys) - complete}
    for c in complete:
        over = [t for tier in tiers for t in tier["targets"] if val(c, t) > tier.get("max_us", float("inf"))]
        if over:
            reasons[c] = "over the hard limit on " + ", ".join(over)
    pool, ranked = complete - set(reasons), []
    while pool:
        survivors = pool
        for tier in tiers[:-1]:
            b = min(score(c, tier) for c in survivors)
            survivors = {c for c in survivors if score(c, tier) <= b * (1 + tier.get("tolerance_pct", 5) / 100)}
        winner = min(survivors, key=lambda c: tuple(score(c, t) for t in reversed(tiers)) + (c,))
        ranked.append(winner)
        pool = pool - {winner}
    return ranked, reasons, floor


def describe_goal(goal):
    metric = goal.get("metric", "p50")
    parts = []
    for i, tier in enumerate(goal["tiers"], 1):
        extra = [f"within {tier.get('tolerance_pct', 5)}% counts as a tie"] if i < len(goal["tiers"]) else []
        if "max_us" in tier:
            extra.append(f"hard limit {tier['max_us']} us")
        parts.append(f"tier {i}: {' + '.join(tier['targets'])} ({metric}" + "".join(f", {x}" for x in extra) + ")")
    return " -> ".join(parts) + f". Keep the top {goal.get('keep', 1)}."


def flat(d, pre=""):
    for k, v in d.items():
        yield from flat(v, f"{pre}{k}.") if isinstance(v, dict) else [(pre + k, v)]


def env_table(per_host):
    """{instance: {...}} -> rows [field, value]; hosts that differ are listed as 'value (n hosts)'."""
    seen = {}
    for iid, d in per_host.items():
        for k, v in flat(d):
            seen.setdefault(k, {}).setdefault(str(v), []).append(iid)
    return [[k, next(iter(v)) if len(v) == 1 else "; ".join(f"{x} ({len(i)} hosts)" for x, i in v.items())]
            for k, v in seen.items()]


def env_section(rows, env, meta, n_cands):
    tls = sorted({r["phases_us"]["tls_info"] for r in rows if (r.get("phases_us") or {}).get("tls_info")})
    secs = (meta or {}).get("duration_secs", "?")
    out = ["## Test environment and method (line these up before comparing numbers)", "",
           f"- **Probe**: Rust, tokio current-thread runtime, rustls (ring) TLS, tokio-tungstenite WebSocket, built with "
           f"`cargo build --release` on each instance (source hash per host below). TLS negotiated: "
           f"{', '.join(tls) if tls else 'not recorded (older probe)'}.",
           "- **Kernel bypass: none.** Plain Linux sockets through the kernel TCP/IP stack (epoll). No DPDK, AF_XDP/XDP, "
           "io_uring or socket busy polling (`net.core.busy_poll` / `busy_read` below), ENA Express as listed below.",
           "- **OS tuning: none on purpose.** Stock AMI kernel parameters: no sysctl, IRQ affinity, isolcpus, governor or "
           "hyper-threading changes. The only thing done is pinning the RTT probe to CPU 1 and the market-data feed process "
           "to CPU 0 (`taskset`; CPU 0 on single-vCPU types). Small types have one core with two hyper-threads: if "
           "`cpu0_thread_siblings` below is `0-1`, those two CPUs share a core, so a feed target can disturb the RTT probe a little.",
           "- **Sockets**: TCP_NODELAY on; one WebSocket connection per (target, exchange IP); one request in flight per "
           "connection, one request per second, send times staggered; the first 5 answers of each connection are dropped as warm-up.",
           "- **Timestamps** (Rust `Instant`, CLOCK_MONOTONIC, so no time sync is involved): req/resp RTT starts right before the "
           "socket write (frame already built) and ends when the response frame has been read from the TLS stream (decrypted, "
           "before matching or JSON parsing). TCP handshake RTT is `connect()` call -> return, the connection closed right away; the "
           "`tcp` target samples it every interval for the whole run (first 5 dropped), the 5 startup connects feed the other tables. "
           "TLS and WS upgrade are timed on the first connection of each IP.",
           "- **Network path**: instance public IPv4 -> Internet Gateway -> exchange public IP. No NAT gateway, VPN, PrivateLink, "
           "peering or Transit Gateway unless the run was given `--route`. Security group: egress only.",
           f"- **Placement and window**: cluster mode gives each candidate its own placement group; partition mode assigns candidate index i to group i // 7 and partition i % 7 + 1. Each further round gets a fresh group per AZ. "
           f"{n_cands} candidates probed at the same moment for {secs} s. Exchange hostnames are resolved on each instance at start, "
           "so the IP sets can differ between instances.", ""]
    if env:
        out += ["### EC2 (from the API)", "", table(["Field", "Value"], env_table(env["ec2"])), "",
                "### Instance OS and tuning (read on the instances)", "", table(["Field", "Value"], env_table(env["hosts"])), ""]
    else:
        out += ["(no env.json in this result directory: it was collected by an older version)", ""]
    return out


def pg(c):
    """Placement group, with the partition number when it is a partition group."""
    name = c.get("placement_group", c.get("cpg"))  # old saved results used "cpg"
    return f"{name} p{c['partition']}" if c.get("partition") else str(name)


def render(rows, cands, goal, env=None, meta=None):
    """rows: one dict per (instance, target, ip) = candidate fields + probe result fields."""
    metric = goal.get("metric", "p50")
    order = lambda r: (r["stats_us"][metric], r["stats_us"]["p99"])
    feed_rows = [r for r in rows if r.get("kind") == "feed"]  # real market-data lag, shown apart, never ranked
    rows = [r for r in rows if r.get("kind") != "feed"]
    ph = lambda r, k: (r.get("phases_us") or {}).get(k) if (r.get("phases_us") or {}).get(k) is not None else "-"
    names = sorted({r["name"] for r in rows})
    unknown = [t for tier in goal["tiers"] for t in tier["targets"] if t not in names]
    if unknown:
        sys.exit(f"goal names unknown targets {unknown}; results have {names}")
    # best[target][candidate key] = that instance's fastest exchange IP row
    best = {n: {} for n in names}
    for r in rows:
        if r["stats_us"]:
            cur = best[r["name"]].get(r["key"])
            if cur is None or order(r) < order(cur):
                best[r["name"]][r["key"]] = r
    ranked, reasons, floor = rank(best, list(cands), goal)
    keep = ranked[: goal.get("keep", 1)]
    goal_targets = [t for tier in goal["tiers"] for t in tier["targets"]]

    def cell(k, t):
        r = best[t].get(k)
        if not r:
            return "-"
        v = r["stats_us"][metric]
        return f"{v} ({v / floor[t]:.2f}x)" if t in floor else str(v)

    c = lambda k: cands[k]
    ident = lambda k: [k, c(k)["az_id"], pg(c(k)), c(k)["instance_id"], c(k)["public_ip"]]
    out = ["# EC2 Hunting Report", "",
           "All times in us. Each instance is scored with its fastest endpoint IP (the exchange resolves to several IPs; "
           "every instance probes all of them). Columns:", "",
           "- **TCP handshake RTT**: SYN -> SYN/ACK, the pure network round trip; median of 5 connects.",
           "- **TCP handshake RTT p50/p95/p99** (target kind `tcp`): the same handshake sampled continuously, one per interval, "
           "for the whole test (hundreds of samples per IP). Pure network, no exchange processing: the cleanest placement metric.",
           "- **TLS**: TLS handshake after the TCP connect (network round trips plus crypto on both ends).",
           "- **WS upgrade**: HTTP upgrade request -> 101 response, one round trip plus server processing.",
           "- **Req/resp RTT p50/p95/p99**: WebSocket request sent -> full response received, once per second: network round trip "
           "plus the exchange's processing of the request. It is ranked only when the goal uses a request/response target.",
           "- **Market data lag** (when a feed target is present): local wall clock minus the exchange's event "
           "timestamp (ms resolution) on live pushes. It includes the clock offset between exchange and instance, so "
           "compare instances with each other, not as an absolute latency.", "",
           "WARN = loss, reconnects or no samples.", "",
           "## Goal", "", goal.get("description", "(no description)"), "", describe_goal(goal), "",
           "## Ranking by goal", "", table(
               ["#", "Decision", "Candidate", "AZ ID", "Placement group", "Instance", "Public IP"] + [f"{t} {metric}" for t in goal_targets],
               [[i + 1, "KEEP" if k in keep else "terminate"] + ident(k) + [cell(k, t) for t in goal_targets]
                for i, k in enumerate(ranked)] +
               [["-", f"terminate ({why})"] + ident(k) + [cell(k, t) for t in goal_targets]
                for k, why in sorted(reasons.items())]), ""]

    for n in names:
        ranked_rows = sorted(best[n].values(), key=order)
        out += [f"## {n}", ""]
        if not ranked_rows:
            out += ["No valid samples, see the detail table.", ""]
            continue
        if ranked_rows[0].get("kind") == "tcp":
            out += [table(["#", "AZ ID", "Placement group", "Instance", "Public IP", "Fastest endpoint IP", "TCP handshake RTT min", "p50", "p95",
                           "p99", "Samples/lost"],
                          [[i + 1, r["az_id"], pg(r), r["instance_id"], r["public_ip"], r["ip"], r["stats_us"]["min"],
                            r["stats_us"]["p50"], r["stats_us"]["p95"], r["stats_us"]["p99"], f"{r['samples']}/{r['lost']}"]
                           for i, r in enumerate(ranked_rows)]), ""]
        else:
            out += [table(["#", "AZ ID", "Placement group", "Instance", "Public IP", "Fastest endpoint IP", "TCP handshake RTT", "TLS", "WS upgrade",
                           "Req/resp RTT p50", "Req/resp p95", "Req/resp p99", "Samples/lost"],
                          [[i + 1, r["az_id"], pg(r), r["instance_id"], r["public_ip"], r["ip"], ph(r, "tcp_p50"),
                            ph(r, "tls"), ph(r, "ws"), r["stats_us"]["p50"], r["stats_us"]["p95"], r["stats_us"]["p99"],
                            f"{r['samples']}/{r['lost']}"]
                           for i, r in enumerate(ranked_rows)]), ""]
        by_az = {}
        for r in ranked_rows:
            by_az.setdefault(r["az_id"], []).append(r["stats_us"]["p50"])
        out += ["Per AZ (min / median of instance-best p50): " + "; ".join(
            f"{az} {min(v)} / {int(statistics.median(v))}" for az, v in sorted(by_az.items(), key=lambda x: min(x[1]))), ""]

    fnames = sorted({r["name"] for r in feed_rows})
    for n in fnames:
        fr = {}
        for r in feed_rows:  # per instance: the endpoint IP with the lowest median lag
            if r["name"] == n and r["stats_us"] and (r["key"] not in fr or r["stats_us"]["p50"] < fr[r["key"]]["stats_us"]["p50"]):
                fr[r["key"]] = r
        out += [f"## {n} (market data lag)", ""]
        if not fr:
            out += ["No valid samples, see the detail table.", ""]
            continue
        out += [table(["#", "AZ ID", "Instance", "Fastest endpoint IP", "Pushes/s", "Samples", "TCP handshake RTT", "TLS", "WS upgrade",
                       "Lag min", "p50", "p95", "p99"],
                      [[i + 1, r["az_id"], r["instance_id"], r["ip"], round(r.get("pushes_per_s", 0), 1), r["samples"],
                        ph(r, "tcp_p50"), ph(r, "tls"), ph(r, "ws"), r["stats_us"]["min"], r["stats_us"]["p50"],
                        r["stats_us"]["p95"], r["stats_us"]["p99"]]
                       for i, r in enumerate(sorted(fr.values(), key=lambda r: r["stats_us"]["p50"]))]), ""]

    out += env_section(rows + feed_rows, env, meta, len(cands))
    out += ["## Detail (every instance x exchange IP)", "", table(
        ["Target", "AZ ID", "Placement group", "Instance", "Public IP", "Exchange IP", "Samples", "Lost", "Errors", "Startup TCP RTT", "TLS",
         "WS upgrade", "Measures", "p50", "p95", "p99", ""],
        [[r["name"], r["az_id"], pg(r), r["instance_id"], r["public_ip"], r["ip"] or "-", r["samples"], r["lost"],
          r["errors"], ph(r, "tcp_p50"), ph(r, "tls"), ph(r, "ws"),
          {"tcp": "TCP handshake RTT", "feed": "market data lag"}.get(r.get("kind"), "req/resp RTT"),
          *((r["stats_us"][p] for p in ("p50", "p95", "p99")) if r["stats_us"] else ("-",) * 3),
          "WARN" if r["lost"] or r["errors"] or not r["samples"] else ""]
         for r in sorted(rows + feed_rows, key=lambda r: (r["name"], order(r) if r["stats_us"] else (float("inf"), 0)))]), ""]

    out += ["## Recommendation", ""]
    if not keep:
        out.append("- No candidate meets the goal. Every candidate will be terminated; consider another round.")
    for k in keep:
        out.append(f"- Keep `{k}`: Placement group `{pg(c(k))}` ({c(k)['az_id']}), instance `{c(k)['instance_id']}` / {c(k)['public_ip']}")
        for t in goal_targets:
            r = best[t][k]
            if r.get("kind") == "tcp":
                out.append(f"  - {t}: fastest endpoint IP `{r['ip']}`: TCP handshake RTT min {r['stats_us']['min']} / "
                           f"p50 {r['stats_us']['p50']} / p99 {r['stats_us']['p99']}")
                continue
            out.append(f"  - {t}: fastest endpoint IP `{r['ip']}`: TCP handshake RTT {ph(r, 'tcp_p50')}, TLS {ph(r, 'tls')}, "
                       f"WS upgrade {ph(r, 'ws')}, req/resp RTT p50 {r['stats_us']['p50']} / p99 {r['stats_us']['p99']}")
    for k in keep:  # the winner's full endpoint IP ranking, fastest first
        for n in names:
            mine = sorted((r for r in rows if r["key"] == k and r["name"] == n and r["stats_us"]), key=order)
            if mine and mine[0].get("kind") == "tcp":
                out += ["", f"### `{k}` -> {n}: every endpoint IP, fastest first", "", table(
                    ["#", "Endpoint IP", "TCP handshake RTT min", "p50", "p95", "p99", "Samples/lost"],
                    [[i + 1, r["ip"], r["stats_us"]["min"], r["stats_us"]["p50"], r["stats_us"]["p95"], r["stats_us"]["p99"],
                      f"{r['samples']}/{r['lost']}"] for i, r in enumerate(mine)])]
            elif mine:
                out += ["", f"### `{k}` -> {n}: every endpoint IP, fastest first", "", table(
                    ["#", "Endpoint IP", "TCP handshake RTT", "TLS", "WS upgrade", "Req/resp RTT p50", "Req/resp p95", "Req/resp p99", "Samples/lost"],
                    [[i + 1, r["ip"], ph(r, "tcp_p50"), ph(r, "tls"), ph(r, "ws"), r["stats_us"]["p50"],
                      r["stats_us"]["p95"], r["stats_us"]["p99"], f"{r['samples']}/{r['lost']}"]
                     for i, r in enumerate(mine)])]
        for r in sorted((r for r in feed_rows if r["key"] == k and r["stats_us"]), key=lambda r: r["stats_us"]["p50"]):
            out.append(f"  - market data lag {r['name']} via `{r['ip']}`: p50 {r['stats_us']['p50']} / p99 {r['stats_us']['p99']}, "
                       f"{round(r.get('pushes_per_s', 0), 1)} pushes/s")
    out += ["", f"Next: `hunt.py prune <results-dir>` keeps {json.dumps(keep)} and terminates the rest."]
    return "\n".join(out) + "\n", keep


def report(results, goal_path, keep_override=None):
    d = Path(results)
    cands = json.loads((d / "candidates.json").read_text())
    by_iid = {c["instance_id"]: dict(c, key=k) for k, c in cands.items()}
    rows = [{**by_iid[f.stem], **r} for f in sorted(d.glob("i-*.json")) for r in json.loads(f.read_text())]
    if not rows:
        sys.exit(f"no results in {d}")
    if goal_path:
        (d / "goal.json").write_text(Path(goal_path).read_text())
    goal = json.loads((d / "goal.json").read_text()) if (d / "goal.json").exists() else {
        "description": "No goal given: every target weighted equally.",
        "tiers": [{"targets": sorted({r["name"] for r in rows if r.get("kind") != "feed"})}], "keep": 1}
    if keep_override:
        goal["keep"] = keep_override
    load = lambda n: json.loads((d / n).read_text()) if (d / n).exists() else None
    text, keep = render(rows, cands, goal, load("env.json"), load("meta.json"))
    (d / "report.md").write_text(text)
    (d / "keep.json").write_text(json.dumps({"keep": keep}))
    print(text)


# ---------------------------------------------------------------- prune

def unsafe_changes(changes, keep, cands, configured_azs):
    """Reject changes beyond removing losers, empty groups, or resources of an emptied AZ."""
    kept_physical = {v for k in keep for v in (cands[k]["instance_id"],
                     cands[k].get("placement_group", cands[k].get("cpg")), cands[k]["subnet_id"])}
    kept_azs = {cands[k]["az_id"] for k in keep}
    empty_azs = set(configured_azs) - kept_azs
    protected = set()
    kept_groups = {cands[k].get("placement_group", cands[k].get("cpg")) for k in keep}
    for key, cand in cands.items():
        index = key.rsplit("-", 1)[1]
        if index.isdigit():
            group = (cand["az_id"], partition_placement(int(index))[0])
            if key in keep or cand.get("placement_group", cand.get("cpg")) in kept_groups:
                protected.add(group)
        elif key in keep:
            protected.add((cand["az_id"], 0))
    kept_instances = {f"Instance{alnum(k)}" for k in keep}
    kept_cpgs = {f"Cpg{alnum(k)}" for k in keep}

    def removable_group(lid, prefix, tail=""):
        for az in configured_azs:
            match = re.fullmatch(rf"{prefix}{alnum(az)}(?:G([1-9][0-9]*))?{tail}", lid)
            if match:
                return (az, int(match.group(1) or 0)) not in protected
        return False

    bad = []
    for ch in changes:
        rc = ch["ResourceChange"]
        typ, lid = rc["ResourceType"], rc["LogicalResourceId"]
        if typ == "AWS::EC2::Instance":
            allowed = lid.startswith("Instance") and lid not in kept_instances
        elif typ == "AWS::EC2::PlacementGroup":
            allowed = (lid.startswith("Cpg") and lid not in kept_cpgs) or removable_group(lid, "Ppg")
        elif typ == "AWS::EC2::LaunchTemplate":
            allowed = removable_group(lid, "LaunchTemplate", rf"P[1-{PARTITIONS}]")
        elif typ == "AWS::EC2::Subnet":
            allowed = lid in {f"Subnet{alnum(az)}" for az in empty_azs}
        elif typ == "AWS::EC2::SubnetRouteTableAssociation":
            allowed = lid in {f"Association{alnum(az)}" for az in empty_azs}
        else:
            allowed = False
        if not (rc["Action"] == "Remove" and rc["ResourceType"] in PRUNABLE
                and rc.get("PhysicalResourceId") not in kept_physical
                and allowed):
            bad.append(f"{rc['Action']} {rc['ResourceType']} {rc['LogicalResourceId']}")
    return bad


def unsafe_round_changes(changes, placement):
    allowed = {"AWS::EC2::Instance", "AWS::EC2::PlacementGroup"}
    if placement == "partition":
        allowed.add("AWS::EC2::LaunchTemplate")
    return [f"{rc['Action']} {rc['ResourceType']} {rc['LogicalResourceId']}"
            for ch in changes for rc in [ch["ResourceChange"]]
            if rc["Action"] != "Add" or rc["ResourceType"] not in allowed]


def prune(results):
    results = Path(results)
    run = results.parent.parent
    keep = json.loads((results / "keep.json").read_text())["keep"]
    cfg = load_cfg(run)
    stack = cfg["stack"]
    if not keep:
        log("nothing to keep: deleting the whole stack")
        return destroy(run)
    cands = candidates(stack)
    missing = [k for k in keep if k not in cands]
    if missing:
        sys.exit(f"kept candidates {missing} are not running any more")
    config = run / "config.json"
    original = config.read_text()
    configured_azs = cfg["az_subnets"]
    cfg["keep"], cfg["new"] = keep, []
    cfg["az_subnets"] = {az: cidr for az, cidr in cfg["az_subnets"].items() if az in {cands[k]["az_id"] for k in keep}}
    config.write_text(json.dumps(cfg, indent=2) + "\n")
    executed = False
    try:
        _, template = synth(run)
        name = "prune-" + time.strftime("%Y%m%d%H%M%S")
        aws("cloudformation", "create-change-set", "--stack-name", stack, "--change-set-name", name,
            "--template-body", f"file://{template}", "--capabilities", "CAPABILITY_IAM")
        try:
            sh("aws", "cloudformation", "wait", "change-set-create-complete", "--stack-name", stack, "--change-set-name", name)
        except subprocess.CalledProcessError:
            reason = aws("cloudformation", "describe-change-set", "--stack-name", stack, "--change-set-name", name)["StatusReason"]
            aws("cloudformation", "delete-change-set", "--stack-name", stack, "--change-set-name", name)
            if "didn't contain changes" in reason:
                print("nothing to prune: only kept candidates are running")
                return
            sys.exit(f"change set failed: {reason}")
        changes = aws("cloudformation", "describe-change-set", "--stack-name", stack, "--change-set-name", name)["Changes"]
        bad = unsafe_changes(changes, keep, cands, configured_azs)
        if bad:
            aws("cloudformation", "delete-change-set", "--stack-name", stack, "--change-set-name", name)
            sys.exit("refusing to prune, the change set does more than remove losers:\n  " + "\n  ".join(bad))
        aws("cloudformation", "execute-change-set", "--stack-name", stack, "--change-set-name", name)
        executed = True
    finally:
        if not executed:
            config.write_text(original)
    log(f"terminating {len(cands) - len(keep)} candidate(s)")
    sh("aws", "cloudformation", "wait", "stack-update-complete", "--stack-name", stack)
    print(json.dumps({"kept": {k: cands[k] for k in keep},
                      "terminated": {k: c["instance_id"] for k, c in cands.items() if k not in keep}}, indent=2))


def partition_placement(index):
    group, partition = divmod(index, PARTITIONS)
    return group, partition + 1


def next_round(run, per_az):
    """Add fresh challengers in every AZ the stack still has, next to the running winners (never touched)."""
    run = Path(run)
    cfg = load_cfg(run)
    if cfg.get("placement", "cluster") == "partition" and per_az != PARTITIONS:
        sys.exit(f"partition rounds require exactly {PARTITIONS} challengers per AZ (one fresh placement group)")
    stack = cfg["stack"]
    cands = candidates(stack)
    if not cands:
        sys.exit("no running candidates: nothing to extend")
    nxt = cfg.setdefault("next_index", {az: cfg["instances_per_az"] for az in cfg["az_subnets"]})
    cfg["keep"] = list(cands)  # whatever runs now are the incumbents
    cfg["az_subnets"] = {az: cidr for az, cidr in cfg["az_subnets"].items() if az in {c["az_id"] for c in cands.values()}}
    cfg["new"] = []
    for az in cfg["az_subnets"]:
        if cfg.get("placement", "cluster") == "partition":
            start = ((nxt[az] + PARTITIONS - 1) // PARTITIONS) * PARTITIONS
            cfg["new"] += [f"{az}-{i}" for i in range(start, start + PARTITIONS)]
            nxt[az] = start + PARTITIONS
        else:
            cfg["new"] += [f"{az}-{nxt[az] + i}" for i in range(per_az)]
            nxt[az] += per_az
    total = len(cfg["keep"]) + len(cfg["new"])
    if total > 33:
        advice = ("keep 1 overall or split AZs into separate runs" if cfg.get("placement", "cluster") == "partition"
                  else "use a smaller PER_AZ")
        sys.exit(f"{total} candidates is over the ~33 the inline template can hold: {advice}")
    config = run / "config.json"
    original = config.read_text()
    config.write_text(json.dumps(cfg, indent=2) + "\n")
    executed = False
    try:
        _, template = synth(run)
        name = "round-" + time.strftime("%Y%m%d%H%M%S")
        aws("cloudformation", "create-change-set", "--stack-name", stack, "--change-set-name", name,
            "--template-body", f"file://{template}", "--capabilities", "CAPABILITY_IAM")
        sh("aws", "cloudformation", "wait", "change-set-create-complete", "--stack-name", stack, "--change-set-name", name)
        changes = aws("cloudformation", "describe-change-set", "--stack-name", stack, "--change-set-name", name)["Changes"]
        bad = unsafe_round_changes(changes, cfg.get("placement", "cluster"))
        if bad:
            aws("cloudformation", "delete-change-set", "--stack-name", stack, "--change-set-name", name)
            sys.exit("refusing to extend, the change set does more than add challengers:\n  " + "\n  ".join(bad))
        aws("cloudformation", "execute-change-set", "--stack-name", stack, "--change-set-name", name)
        executed = True
    finally:
        if not executed:
            config.write_text(original)
    sh("aws", "cloudformation", "wait", "stack-update-complete", "--stack-name", stack)
    print(json.dumps(candidates(stack), indent=2))


# ---------------------------------------------------------------- selftest

def selftest():
    def row(k, name, ip, p50, p99=None):
        return {"key": k, "name": name, "host": "h", "ip": ip, "samples": 600, "lost": 0, "errors": 0,
                "stats_us": {"p50": p50, "p95": p99 or p50, "p99": p99 or p50}}
    cands = {k: {"az_id": k[:3], "cpg": f"g-{k}", "instance_id": f"i-{k}", "public_ip": "1.1.1.1", "subnet_id": f"s-{k[:3]}"}
             for k in ("az1-a", "az1-b", "az4-c", "az4-d", "az4-e")}
    rows = [row("az1-a", "okx", "x", 1000), row("az1-a", "bn", "p", 900),
            row("az1-b", "okx", "x", 1030), row("az1-b", "bn", "p", 750), row("az1-b", "bn", "q", 700),  # best IP q
            row("az4-c", "okx", "x", 1200), row("az4-c", "bn", "p", 600),
            row("az4-d", "bn", "p", 500)]  # no okx data; az4-e has no results at all
    rows = [{**cands[r["key"]], **r} for r in rows]
    pick = lambda goal: render(rows, cands, goal)[1]
    # Order leg first: okx within 5% of the best (a, b), then the fastest bn among them -> b.
    two_tier = {"tiers": [{"targets": ["okx"], "tolerance_pct": 5}, {"targets": ["bn"]}], "keep": 1}
    assert pick(two_tier) == ["az1-b"], pick(two_tier)
    assert pick({"tiers": [{"targets": ["bn"]}], "keep": 2}) == ["az4-d", "az4-c"]
    # Balanced: a=(1+1.5)/2=1.25, b=(1.03+1.167)/2=1.098, c=(1.2+1)/2=1.1 -> b
    assert pick({"tiers": [{"targets": ["okx", "bn"]}]}) == ["az1-b"]
    assert pick({"tiers": [{"targets": ["okx"], "max_us": 1010}, {"targets": ["bn"]}]}) == ["az1-a"]
    assert pick({"tiers": [{"targets": ["okx"], "max_us": 900}]}) == []
    text, _ = render(rows, cands, two_tier)
    assert "fastest endpoint IP `q`" in text and "terminate (no data for every goal target)" in text
    # phases and feed rows: shown, never ranked
    ph_rows = [dict(r, phases_us={"tcp_min": 400, "tcp_p50": 450, "tls": 6000, "ws": 900}) for r in rows]
    feed = dict(cands["az1-b"], key="az1-b", name="feed", kind="feed", ip="f", samples=900, lost=0, errors=0, pushes_per_s=50.0,
                stats_us={"min": 1, "p50": -200, "p95": 5, "p99": 9}, phases_us={"tcp_p50": 450, "tls": 6000, "ws": 900})
    text, keep = render(ph_rows + [feed], cands, two_tier)
    assert "Kernel bypass: none" in text and "no env.json" in text
    tcp_rows = [dict(r, name="tcp", kind="tcp", stats_us={"min": r["stats_us"]["p50"] - 5, **r["stats_us"]}) for r in rows if r["name"] == "bn"]
    text, keep = render(tcp_rows, cands, {"tiers": [{"targets": ["tcp"]}], "keep": 1})
    assert keep == ["az4-d"] and "TCP handshake RTT min" in text.split("## Recommendation")[1], text
    tcp_rows = [dict(r, name="tcp", kind="tcp", stats_us={"min": r["stats_us"]["p50"] - 5, **r["stats_us"]}) for r in rows if r["name"] == "bn"]
    text, keep = render(tcp_rows, cands, {"tiers": [{"targets": ["tcp"]}], "keep": 1})
    assert keep == ["az4-d"] and "TCP handshake RTT min" in text and "TCP handshake RTT" in text.split("## Recommendation")[1], text
    env = {"ec2": {"i-a": {"instance_type": "c8i.large", "ena_express": "off"}, "i-b": {"instance_type": "c8i.large", "ena_express": "off"}},
           "hosts": {"i-a": {"kernel": "6.1", "sysctl": {"net.core.busy_poll": "0"}}, "i-b": {"kernel": "6.2", "sysctl": {"net.core.busy_poll": "0"}}}}
    text, _ = render(ph_rows, cands, two_tier, env, {"duration_secs": 600})
    assert "| instance_type | c8i.large |" in text and "6.1 (1 hosts); 6.2 (1 hosts)" in text and "net.core.busy_poll | 0 |" in text, text
    text, keep = render(ph_rows + [feed], cands, two_tier)
    assert keep == ["az1-b"] and "market data lag" in text and "| 450 | 6000 | 900 |" in text and "every endpoint IP, fastest first" in text
    instances = [{"InstanceId": f"i-{n}", "InstanceType": "m8azn.large", "ImageId": "ami-test",
                  "Placement": {"GroupName": "shared", "PartitionNumber": n, "Tenancy": "default"},
                  "Monitoring": {"State": "disabled"}} for n in (1, 2)]
    with patch.dict(globals(), {
        "aws": lambda *args: {"NetworkInterfaces": []} if args[1] == "describe-network-interfaces" else instances,
        "ssm": lambda *args: {"i-1": "{}", "i-2": "{}"},
    }):
        placement = collect_env(["i-1", "i-2"], {"az1-0": {"instance_id": "i-1", "az_id": "az1"},
                                                   "az1-1": {"instance_id": "i-2", "az_id": "az1"}})["ec2"]
    assert placement["i-1"]["placement"] == placement["i-2"]["placement"] == "partition placement group shared, tenancy default"

    change = lambda action, typ, lid, pid: {"ResourceChange": {"Action": action, "ResourceType": typ,
                                                               "LogicalResourceId": lid, "PhysicalResourceId": pid}}
    keep = ["az1-b"]
    configured_azs = {"az1", "az4", "az9"}
    assert not unsafe_changes([change("Remove", "AWS::EC2::Instance", "Instanceaz1a", "i-az1-a"),
                               change("Remove", "AWS::EC2::Subnet", "Subnetaz4", "s-az4")], keep, cands, configured_azs)
    assert not unsafe_changes([change("Remove", "AWS::EC2::Instance", "Instanceaz12", "i-az1-2"),
                               change("Remove", "AWS::EC2::PlacementGroup", "Cpgaz12", "g-az1-2")],
                              keep, cands, configured_azs)
    assert unsafe_changes([change("Remove", "AWS::EC2::Instance", "Instanceaz1b", "i-az1-b")], keep, cands, configured_azs)  # winner
    assert unsafe_changes([change("Remove", "AWS::EC2::Subnet", "Subnetaz1", "s-az1")], keep, cands, configured_azs)  # winner's subnet
    assert unsafe_changes([change("Modify", "AWS::EC2::LaunchTemplate", "LaunchTemplate", "lt-1")], keep, cands, configured_azs)
    assert not unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz4P1", "lt-az4-1")], keep, cands, configured_azs)
    assert not unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz9P1", "lt-az9-1")], keep, cands, configured_azs)
    assert unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1P1", "lt-az1-1")], keep, cands, configured_azs)
    assert unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateOtherP1", "lt-other-1")], keep, cands, configured_azs)
    shared = {k: dict(c, cpg=f"g-{c['az_id']}") for k, c in cands.items()}
    assert unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-az1")], keep, shared, configured_azs)
    assert not unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz4", "g-az4")], keep, shared, configured_azs)
    generic = {k: dict({field: value for field, value in c.items() if field != "cpg"},
                       placement_group=f"g-{c['az_id']}") for k, c in cands.items()}
    assert unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-az1")], keep, generic, configured_azs)
    group_cands = {f"az1-{n}": {"az_id": "az1", "instance_id": f"i-{n}",
                                "placement_group": f"g-az1-{n // 7}", "partition": n % 7 + 1,
                                "subnet_id": "s-az1"} for n in (0, 7, 8)}
    assert [partition_placement(n) for n in (0, 1, 6, 7, 8, 13, 14)] == [
        (0, 1), (0, 2), (0, 7), (1, 1), (1, 2), (1, 7), (2, 1)]
    assert not unsafe_changes([change("Remove", "AWS::EC2::Instance", "Instanceaz10", "i-0"),
                               change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-az1-0"),
                               *[change("Remove", "AWS::EC2::LaunchTemplate", f"LaunchTemplateaz1P{p}", f"lt-0-{p}")
                                 for p in range(1, 8)]], ["az1-7"], group_cands, {"az1"})
    assert unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-az1-0")],
                          ["az1-0"], group_cands, {"az1"})
    assert unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1P1", "lt-0-1")],
                          ["az1-0"], group_cands, {"az1"})
    assert unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1G1", "g-az1-1")],
                          ["az1-7"], group_cands, {"az1"})
    assert unsafe_changes([change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1G1P1", "lt-1-1")],
                          ["az1-7"], group_cands, {"az1"})
    assert not unsafe_changes([change("Remove", "AWS::EC2::Instance", "Instanceaz17", "i-7"),
                               change("Remove", "AWS::EC2::Instance", "Instanceaz18", "i-8"),
                               change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1G1", "g-az1-1"),
                               *[change("Remove", "AWS::EC2::LaunchTemplate", f"LaunchTemplateaz1G1P{p}", f"lt-1-{p}")
                                 for p in range(1, 8)]], ["az1-0"], group_cands, {"az1"})
    assert not unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1G2", "g-az1-2"),
                               change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1G2P1", "lt-2-1")],
                              ["az1-0"], group_cands, {"az1"})
    assert unsafe_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-az1-0"),
                           change("Remove", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1P1", "lt-0-1")],
                          ["az1-0"], group_cands, {"az1"})
    assert not unsafe_round_changes([change("Add", "AWS::EC2::Instance", "Instanceaz18", None)], "partition")
    assert not unsafe_round_changes([change("Add", "AWS::EC2::Instance", "Instanceaz17", None),
                                     change("Add", "AWS::EC2::PlacementGroup", "Ppgaz1G1", None),
                                     change("Add", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1G1P1", None)], "partition")
    assert unsafe_round_changes([change("Modify", "AWS::EC2::LaunchTemplate", "LaunchTemplateaz1P1", "lt-1")], "partition")
    assert unsafe_round_changes([change("Remove", "AWS::EC2::PlacementGroup", "Ppgaz1", "g-1")], "partition")
    assert not unsafe_round_changes([change("Add", "AWS::EC2::PlacementGroup", "Cpgaz18", None)], "cluster")
    assert pg({"cpg": "group", "partition": 4}) == "group p4"
    assert pg({"cpg": "group", "partition": None}) == "group"
    assert pg({"placement_group": "group", "partition": 4}) == "group p4"
    round_cands = {"az1-0": dict(group_cands["az1-0"], public_ip="1.1.1.1"),
                   "az1-7": dict(group_cands["az1-7"], public_ip="1.1.1.2")}
    round_rows = [{**round_cands[k], **row(k, "tcp", "x", latency)} for k, latency in
                  (("az1-0", 900), ("az1-7", 500))]
    text, keep = render(round_rows, round_cands, {"tiers": [{"targets": ["tcp"]}], "keep": 1})
    ranking = text.split("## Ranking by goal")[1].split("## tcp")[0]
    assert keep == ["az1-7"] and "g-az1-0 p1" in ranking and "g-az1-1 p1" in ranking
    assert "| az1-0 |" in ranking and "| az1-7 |" in ranking
    sync = probe_sync_commands()
    assert f"test -x {BIN}" in sync[0]
    assert "pipefail" in sync[-1] and f"rm -f {BIN}" in sync[-1]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        config = tmp / "config.json"
        original = json.dumps({"stack": "offline-hunt", "az_subnets": {"az1": "10.0.0.0/27"},
                               "instances_per_az": 1, "placement": "partition", "keep": [],
                               "user_data": "pinned"})
        config.write_text(original)
        template = tmp / "cdk.out" / "offline-hunt.template.json"
        template.parent.mkdir()
        template.write_bytes(b"x" * (TEMPLATE_LIMIT + 1))
        with patch.dict(globals(), {"cdk": lambda *args: None}):
            try:
                synth(tmp)
            except SystemExit as e:
                assert "keep 1 overall or split AZs" in str(e) and "fewer candidates per AZ" not in str(e)
            else:
                assert False, "oversized partition template was accepted"
        test_cands = {"az1-0": {"az_id": "az1", "instance_id": "i-az1-0", "placement_group": "g-az1",
                                "subnet_id": "s-az1"}}
        bad_change = change("Modify", "AWS::EC2::Instance", "Instanceaz10", "i-az1-0")
        fake_aws = lambda *args: {"Changes": [bad_change]} if args[1] == "describe-change-set" else {}
        staged = []
        def fake_synth(run):
            staged.append(load_cfg(run))
            return staged[-1], tmp / "template.json"
        with patch.dict(globals(), {"aws": fake_aws, "sh": lambda *args: "",
                                    "synth": fake_synth,
                                    "candidates": lambda stack: test_cands}):
            try:
                next_round(tmp, 5)
            except SystemExit as e:
                assert "exactly 7" in str(e)
            assert config.read_text() == original
            oversized = {f"az1-{n}": dict(test_cands["az1-0"], instance_id=f"i-{n}") for n in range(27)}
            with patch.dict(globals(), {"candidates": lambda stack: oversized}):
                try:
                    next_round(tmp, 7)
                except SystemExit as e:
                    assert "keep 1 overall or split AZs" in str(e) and "PER_AZ" not in str(e)
                else:
                    assert False, "oversized partition round was accepted"
            assert config.read_text() == original
            try:
                next_round(tmp, 7)
            except SystemExit as e:
                assert "refusing to extend" in str(e)
            assert staged[-1]["new"] == [f"az1-{n}" for n in range(7, 14)]
            assert staged[-1]["next_index"]["az1"] == 14
            assert config.read_text() == original
            results = tmp / "results" / "first"
            results.mkdir(parents=True)
            (results / "keep.json").write_text(json.dumps({"keep": ["az1-0"]}))
            try:
                prune(results)
            except SystemExit as e:
                assert "refusing to prune" in str(e)
            assert config.read_text() == original
        resources = [{"ResourceType": "AWS::EC2::PlacementGroup", "PhysicalResourceId": "g-old",
                      "LogicalResourceId": "Ppgaz1"},
                     {"ResourceType": "AWS::EC2::PlacementGroup", "PhysicalResourceId": "g-new",
                      "LogicalResourceId": "Ppgaz1G1"}]
        deletes = []
        def fake_destroy_aws(*args):
            if args[1] == "describe-stack-resources":
                return {"StackResources": resources}
            if args[1] == "delete-stack":
                deletes.append(args)
            return {}
        def fake_wait(*args):
            if len(deletes) == 1:
                raise subprocess.CalledProcessError(1, args)
        with patch.dict(globals(), {
            "aws": fake_destroy_aws, "sh": fake_wait, "log": lambda msg: None,
            "print": lambda *args, **kwargs: None,
            "foreign_instances": lambda stack, name, values: (
                [{"Placement": {"GroupName": "g-new"}}] if name == "placement-group-name" and "g-new" in values else []),
        }):
            try:
                destroy(tmp)
            except SystemExit as e:
                assert "--retain" in str(e)
            assert not deletes
            destroy(tmp, True)
        assert len(deletes) == 2 and "--retain-resources" not in deletes[0]
        assert deletes[1][-2:] == ("--retain-resources", "Ppgaz1G1")
    with tempfile.TemporaryDirectory() as tmp:
        azs = ["use1-az1", "use1-az2", "use1-az3"]
        def preflight_aws(*args):
            name = args[1]
            if name == "describe-vpcs":
                return {"Vpcs": [{"CidrBlockAssociationSet": [
                    {"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}}]}]}
            if name == "describe-vpc-attribute":
                return {"EnableDnsSupport": {"Value": True}}
            if name == "describe-internet-gateways":
                return {"InternetGateways": [{"InternetGatewayId": "igw-test"}]}
            if name == "describe-route-tables":
                return {"RouteTables": []}
            if name == "describe-network-acls":
                return {"NetworkAcls": [{"Entries": [
                    {"Egress": e, "RuleNumber": 100, "RuleAction": "allow", "Protocol": "-1",
                     "CidrBlock": "0.0.0.0/0"} for e in (False, True)]}]}
            if name == "describe-subnets":
                return {"Subnets": [{"CidrBlock": "10.0.0.0/27", "SubnetId": "subnet-test"}]}
            if name == "describe-instance-types":
                return {"InstanceTypes": [{"VCpuInfo": {"DefaultVCpus": 2},
                                            "ProcessorInfo": {"SupportedArchitectures": ["arm64"]}}]}
            if name == "describe-instance-type-offerings":
                return {"InstanceTypeOfferings": [{"Location": az} for az in azs]}
            if name == "get-service-quota":
                return {"Quota": {"Value": 1000}}
            if name == "describe-images":
                return {"Images": [{"Architecture": "arm64", "State": "available", "Name": "al2023"}]}
            raise AssertionError(name)
        printed = []
        with patch.dict(globals(), {"RUNS": Path(tmp), "aws": preflight_aws, "sh": lambda *args: "",
                                    "on_demand_price": lambda *args: 1.0,
                                    "standard_vcpus_in_use": lambda: 0,
                                    "template_size_and_max": lambda cfg: (42993, 24409, None),
                                    "offline_template_size": lambda cfg: 69681,
                                    "print": lambda *args, **kwargs: printed.append(" ".join(map(str, args)))}):
            with patch.dict(os.environ, {"AWS_REGION": "us-east-1"}):
                assert preflight("vpc-test", "m8azn.large", 7, azs, 300, {}, "ami-test") == 0
        assert any(line.startswith("WARN") and "keep 1 overall or split AZs" in line for line in printed), printed
        assert not any(line.startswith("FAIL") for line in printed), printed
    python = VENV / "bin" / "python"
    env = {**os.environ, "JSII_RUNTIME_PACKAGE_CACHE": "disabled"}
    if not python.exists() or subprocess.run([str(python), "-c", "import aws_cdk"], env=env,
                                             capture_output=True).returncode:
        print("offline synth skipped (infra CDK venv unavailable)")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cfg = {"stack": "offline-hunt", "region": "us-east-1", "vpc_id": "vpc-12345678",
                   "igw_id": "igw-12345678", "az_subnets": {"use1-az1": "10.0.0.0/27"},
                   "instance_type": "m8azn.large", "instances_per_az": 7, "ami": "ami-12345678",
                   "extra_routes": {}, "keep": [], "placement": "partition"}
            config = tmp / "config.json"
            for mode in ("partition", "partition-round", "partition-pruned-group1",
                         "partition-3az", "partition-4az", "legacy-cluster"):
                cfg.pop("user_data", None)
                cfg["keep"] = []
                cfg.pop("new", None)
                cfg["az_subnets"] = {f"use1-az{n}": f"10.0.{n - 1}.0/27"
                                     for n in range(1, 1 + (3 if mode == "partition-3az" else 4 if mode == "partition-4az" else 1))}
                cfg["instances_per_az"] = 6 if mode == "partition-4az" else 7
                if mode == "partition-round":
                    cfg["keep"] = ["use1-az1-0"]
                    cfg["new"] = [f"use1-az1-{n}" for n in range(7, 14)]
                elif mode == "partition-pruned-group1":
                    cfg["keep"] = ["use1-az1-7"]
                if mode == "legacy-cluster":
                    cfg.pop("placement")
                config.write_text(json.dumps(cfg))
                out = tmp / mode
                synth_env = {**env, "CDK_CONTEXT_JSON": json.dumps({
                    "config": str(config), "aws:cdk:enable-path-metadata": True}), "CDK_OUTDIR": str(out)}
                result = subprocess.run([str(python), str(ROOT / "infra" / "app.py")], cwd=tmp, env=synth_env,
                                        capture_output=True, text=True)
                assert result.returncode == 0, result.stderr
                template = out / "offline-hunt.template.json"
                if mode == "partition-4az":
                    assert template.stat().st_size > TEMPLATE_LIMIT
                    assert template_size_and_max(cfg)[2] == 5
                else:
                    assert template.stat().st_size < TEMPLATE_LIMIT
                if mode == "partition-3az":
                    initial_size, round_size, maximum = template_size_and_max(cfg)
                    assert initial_size < TEMPLATE_LIMIT and round_size < TEMPLATE_LIMIT and maximum is None
                    assert list(round_template_cfg(cfg)["az_subnets"]) == ["use1-az1"]
                resources = json.loads(template.read_text())["Resources"]
                lts = [r for r in resources.values() if r["Type"] == "AWS::EC2::LaunchTemplate"]
                if mode == "partition":
                    assert len(lts) == 7
                    assert sorted(r["Properties"]["LaunchTemplateData"]["Placement"]["PartitionNumber"] for r in lts) == list(range(1, 8))
                    for index in range(7):
                        assert resources[f"Instanceuse1az1{index}"]["Properties"]["LaunchTemplate"]["LaunchTemplateId"] == {
                            "Ref": f"LaunchTemplateuse1az1P{index + 1}"}
                    original_lts = {k: v for k, v in resources.items() if v["Type"] == "AWS::EC2::LaunchTemplate"}
                    pin_user_data(tmp, cfg, template)
                    assert cfg["user_data"] == next(iter(original_lts.values()))["Properties"]["LaunchTemplateData"]["UserData"]
                    result = subprocess.run([str(python), str(ROOT / "infra" / "app.py")], cwd=tmp, env=synth_env,
                                            capture_output=True, text=True)
                    assert result.returncode == 0, result.stderr
                    repeated = json.loads(template.read_text())["Resources"]
                    assert original_lts == {k: v for k, v in repeated.items() if v["Type"] == "AWS::EC2::LaunchTemplate"}
                    group0 = {k: v for k, v in resources.items() if k == "Ppguse1az1" or k.startswith("LaunchTemplateuse1az1P")}
                    assert len(group0) == 8
                elif mode == "partition-round":
                    assert sum(r["Type"] == "AWS::EC2::PlacementGroup" for r in resources.values()) == 2
                    assert len(lts) == 14
                    assert {k: resources[k] for k in group0} == group0
                    assert all(resources[f"Instanceuse1az1{n}"]["Properties"]["LaunchTemplate"]["LaunchTemplateId"] ==
                               {"Ref": f"LaunchTemplateuse1az1G1P{n - 6}"} for n in range(7, 14))
                elif mode == "partition-pruned-group1":
                    assert "Ppguse1az1" not in resources and "Ppguse1az1G1" in resources
                    assert len(lts) == 7
                elif mode == "legacy-cluster":
                    assert len(lts) == 1
                    assert sum(r["Type"] == "AWS::EC2::PlacementGroup" for r in resources.values()) == 7
    print("selftest ok")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("perms")
    s = sub.add_parser("preflight")
    s.add_argument("vpc"), s.add_argument("type"), s.add_argument("per_az", type=int), s.add_argument("az_ids", nargs="+")
    s.add_argument("--secs", type=int, default=MIN_SECS)
    s.add_argument("--ami", help="AMI id or SSM public parameter path (default: latest Amazon Linux 2023)")
    s.add_argument("--route", action="append", default=[], help="CIDR=pcx-xxx or CIDR=tgw-xxx")
    s.add_argument("--placement", choices=["partition", "cluster"], default="partition",
                   help="partition: 7 partitions per group, a fresh group each round (default); "
                        "cluster: one cluster placement group per candidate")
    sub.add_parser("deploy").add_argument("run")
    s = sub.add_parser("run")
    s.add_argument("run"), s.add_argument("targets"), s.add_argument("secs", type=int)
    s.add_argument("--smoke", action="store_true")
    s = sub.add_parser("report")
    s.add_argument("results"), s.add_argument("--goal"), s.add_argument("--keep", type=int, help="override goal keep")
    s = sub.add_parser("round")
    s.add_argument("run"), s.add_argument("per_az", type=int,
                                          help="partition: exactly 7 per AZ; cluster: count per AZ")
    sub.add_parser("prune").add_argument("results")
    s = sub.add_parser("destroy")
    s.add_argument("run"), s.add_argument("--retain", action="store_true", help="keep placement groups used by non-hunt instances")
    sub.add_parser("list")
    sub.add_parser("selftest")
    a = p.parse_args()
    if a.cmd == "perms":
        sys.exit(perms())
    elif a.cmd == "preflight":
        sys.exit(preflight(a.vpc, a.type, a.per_az, a.az_ids, a.secs, dict(r.split("=", 1) for r in a.route), a.ami, a.placement))
    elif a.cmd == "deploy":
        deploy(a.run)
    elif a.cmd == "run":
        run_probe(a.run, a.targets, a.secs, a.smoke)
    elif a.cmd == "report":
        report(a.results, a.goal, a.keep)
    elif a.cmd == "round":
        next_round(a.run, a.per_az)
    elif a.cmd == "prune":
        prune(a.results)
    elif a.cmd == "destroy":
        destroy(a.run, a.retain)
    elif a.cmd == "list":
        list_runs()
    else:
        selftest()
