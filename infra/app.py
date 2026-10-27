#!/usr/bin/env python3
"""One hunting run = one CloudFormation stack. Every input comes from the run's config.json
(written by `hunt.py preflight`).

Each candidate instance gets its own cluster placement group, so the winner's CPG can later host
production instances in the same network segment.
"""
import base64
import gzip
import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam

PROBE = Path(__file__).resolve().parent.parent / "probe"
SOURCES = ["Cargo.toml", "Cargo.lock", "src/main.rs"]
# Runs once at first boot. No OS tuning on purpose: every candidate runs the same image and script
# at the same time, so OS noise is common to all of them and cancels out when comparing placements.
BUILD = ("export HOME=/root RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust; "
         "curl --proto '=https' --tlsv1.2 -sSf --retry 10 --retry-all-errors https://sh.rustup.rs"
         " | sh -s -- -y --profile minimal"
         " && /opt/rust/bin/cargo build --release --manifest-path /opt/hunt/probe/Cargo.toml")


def user_data():
    # YAML is a superset of JSON; gzip keeps the probe source well under the 16 KB user data limit.
    cloud_config = "#cloud-config\n" + json.dumps({
        "packages": ["gcc"],
        "write_files": [{"path": f"/opt/hunt/probe/{f}", "content": (PROBE / f).read_text()} for f in SOURCES],
        "runcmd": [["bash", "-c", BUILD]],
    })
    return base64.b64encode(gzip.compress(cloud_config.encode(), mtime=0)).decode()


def alnum(s):
    return "".join(ch for ch in s if ch.isalnum())


app = cdk.App()
cfg = json.loads(Path(app.node.get_context("config")).read_text())
# Legacy synthesizer: deploys with the caller's own credentials and needs no `cdk bootstrap`,
# as long as the template stays under 51,200 bytes and has no assets.
stack = cdk.Stack(app, cfg["stack"], env=cdk.Environment(region=cfg["region"]),
                  synthesizer=cdk.LegacyStackSynthesizer(), analytics_reporting=False)
vpc_id = cfg["vpc_id"]

igw_id, attachment = cfg["igw_id"], None
if not igw_id:  # a VPC can only have one IGW, so an attached one is reused
    igw = ec2.CfnInternetGateway(stack, "Igw")
    attachment = ec2.CfnVPCGatewayAttachment(stack, "IgwAttachment", vpc_id=vpc_id, internet_gateway_id=igw.ref)
    igw_id = igw.ref

route_table = ec2.CfnRouteTable(stack, "RouteTable", vpc_id=vpc_id)
# Straight to the IGW: behind a NAT gateway every candidate would share the NAT's path,
# so we'd measure the NAT's placement instead of each instance's.
default_route = ec2.CfnRoute(stack, "DefaultRoute", route_table_id=route_table.ref,
                             destination_cidr_block="0.0.0.0/0", gateway_id=igw_id)
if attachment:
    default_route.add_resource_dependency(attachment)
for cidr, target in cfg["extra_routes"].items():  # dedicated exchange endpoints over peering / TGW
    ec2.CfnRoute(stack, f"Route{alnum(cidr)}", route_table_id=route_table.ref, destination_cidr_block=cidr,
                 vpc_peering_connection_id=target if target.startswith("pcx-") else None,
                 transit_gateway_id=target if target.startswith("tgw-") else None)

sg = ec2.CfnSecurityGroup(stack, "SecurityGroup", vpc_id=vpc_id, group_description="aws-ec2-hunting probes, egress only",
                          security_group_egress=[ec2.CfnSecurityGroup.EgressProperty(ip_protocol="-1", cidr_ip="0.0.0.0/0")])
role = iam.Role(stack, "Role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
                managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")])
profile = iam.CfnInstanceProfile(stack, "InstanceProfile", roles=[role.role_name])
launch_template = ec2.CfnLaunchTemplate(stack, "LaunchTemplate", launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
    image_id=cfg["ami"],  # pinned by preflight, so a later update (prune) never replaces the kept instances
    instance_type=cfg["instance_type"],
    iam_instance_profile=ec2.CfnLaunchTemplate.IamInstanceProfileProperty(arn=profile.attr_arn),
    security_group_ids=[sg.attr_group_id],
    instance_initiated_shutdown_behavior="terminate",
    metadata_options=ec2.CfnLaunchTemplate.MetadataOptionsProperty(http_tokens="required"),
    # Pinned in config.json on first synth: a later round must never change the launch template, or CloudFormation
    # would replace the running winners. The probe source is synced over SSM instead (hunt.py run).
    user_data=cfg.get("user_data") or user_data()))

for az_id, cidr in cfg["az_subnets"].items():
    subnet = ec2.CfnSubnet(stack, f"Subnet{alnum(az_id)}", vpc_id=vpc_id, cidr_block=cidr, availability_zone_id=az_id,
                           map_public_ip_on_launch=True, tags=[cdk.CfnTag(key="Name", value=f"{cfg['stack']}-{az_id}")])
    association = ec2.CfnSubnetRouteTableAssociation(stack, f"Association{alnum(az_id)}", subnet_id=subnet.ref,
                                                     route_table_id=route_table.ref)
    if cfg["keep"]:  # after a prune: the winners, plus the fresh challengers of the next round
        keys = [k for k in cfg["keep"] + cfg.get("new", []) if k.rsplit("-", 1)[0] == az_id]
    else:
        keys = [f"{az_id}-{i}" for i in range(cfg["instances_per_az"])]
    for key in keys:
        cpg = ec2.CfnPlacementGroup(stack, f"Cpg{alnum(key)}", strategy="cluster")
        instance = ec2.CfnInstance(
            stack, f"Instance{alnum(key)}", subnet_id=subnet.ref, placement_group_name=cpg.ref,
            launch_template=ec2.CfnInstance.LaunchTemplateSpecificationProperty(
                launch_template_id=launch_template.ref, version=launch_template.attr_latest_version_number),
            tags=[cdk.CfnTag(key="Name", value=f"{cfg['stack']}-{key}"), cdk.CfnTag(key="hunt:key", value=key)])
        instance.add_resource_dependency(association)
        instance.add_resource_dependency(default_route)

app.synth()
