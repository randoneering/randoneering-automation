import datetime
import json
import logging
import re
import secrets
import sys

import boto3
import botocore
import yaml

security_group_mapping = {
    "postgres": "db_postgres_default",
    "aurora-postgresql": "db_postgres_default",
    "mysql": "db_mysql_default",
    "aurora-mysql": "db_mysql_default",
}

log_mapping = {
    "postgres": ["postgresql"],
    "aurora-postgresql": ["postgresql"],
    "mysql": ["audit", "error", "slowquery"],
    "aurora-mysql": ["audit", "error", "slowquery"],
}


# Load the options.yml file for user selection
OPTIONS_PATH = "./config/options.yml"
try:
    with open(OPTIONS_PATH, "r") as f:
        OPTIONS = yaml.safe_load(f)
except Exception as e:
    logging.error(f"Failed to load options.yaml: {e}")


# Option list function that will be used in the define_request() function
def option_list(prompt: str, items):
    items = list(items)
    print(prompt)
    for i, item in enumerate(items, start=1):
        print(f"  {i}. {item}")
    while True:
        try:
            choice = int(input("Select a number: "))
            if 1 <= choice <= len(items):
                return items[choice - 1]
        except ValueError:
            pass
        print("Invalid selection – try again.")


# Initialize logging.
def enable_logging():
    log_file = "/mnt/logs/database_provisioning/" + datetime.datetime.now().strftime(
        "database_provisioning_%Y_%m_%d_%H_%M.log"
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(log_file)],
    )


# Get AWS credentials from IAM role to make api calls
def aws_credentials(region, account):
    role_arn = f"arn:aws:iam::{account}:role/{iam_role}"
    try:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="database_provisioning",
        )["Credentials"]
        region = region
        aws_access_key_id = creds["AccessKeyId"]
        aws_secret_access_key = creds["SecretAccessKey"]
        aws_session_token = creds["SessionToken"]
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to initialize aws credentials: {e}")
        sys.exit(1)
    return aws_access_key_id, aws_secret_access_key, aws_session_token, region


# Create rds client session
def rds_client(aws_access_key_id, aws_secret_access_key, aws_session_token, region):
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region,
    )
    rds = session.client("rds")

    return rds


# Create ksm client session
def kms_client(aws_access_key_id, aws_secret_access_key, aws_session_token, region):
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region,
    )
    kms = session.client("kms")

    return kms


# Create ec2 client session
def ec2_client(aws_access_key_id, aws_secret_access_key, aws_session_token, region):
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region,
    )
    ec2 = session.client("ec2")

    return ec2


# Create route53 client session
def route53_client(aws_access_key_id, aws_secret_access_key, aws_session_token, region):
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region,
    )
    route53 = session.client("route53")

    return route53


# Define variables to fuel the rest of the functions
def define_request():
    # Simple function to get variables for creating resources. Nothing fancy
    dbname = input("Enter database name: ")
    service = input("Enter name of the service: ")

    # Fueled by the options_list() function
    env = option_list(
        "Select the environment you are deploying to:", OPTIONS["environments"].keys()
    )
    engine = option_list("Select the database engine:", OPTIONS["engines"])
    engine_version = option_list(
        f"Select the version for {engine}:", OPTIONS["engine_versions"][engine]
    )
    instance_class = option_list(
        "Select the instance class:", OPTIONS["instance_classes"]
    )
    storage_type = "gp3"  # leaving hardcoded until we move to a different default.
    storage = 100
    vpc = OPTIONS["environments"][env]["vpc"]
    region = OPTIONS["environments"][env]["region"]
    tags = [
        {"Key": "owner", "Value": "justin@randoneering.tech"},
        {"Key": "env", "Value": f"{env}"},
        {"Key": "app", "Value": f"{service}"},
    ]
    security_group = security_group_mapping[engine]
    subnet_group = OPTIONS["environments"][env]["subnet_group"]
    logs = log_mapping[engine]
    hosted_zone_id = OPTIONS["environments"][env]["hosted_zone_id"]
    account = OPTIONS["environments"][env]["account_id"]
    return (
        dbname,
        service,
        engine,
        engine_version,
        env,
        instance_class,
        account,
        tags,
        security_group,
        subnet_group,
        logs,
        region,
        hosted_zone_id,
        vpc,
        storage,
        storage_type,
    )


# Generate a random password for the master username (randoneering)
def random_password():
    logging.info("Generating password for master password")
    try:
        characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-.0123456789"
        length = 21
        password = "".join(secrets.choice(characters) for _ in range(length))
        logging.info("Random password generated!")

    except Exception as e:
        logging.error(f"Error creating random password: {e}")
        raise
    return password


# Define the default param group to use to generate a new parameter group
def default_param_group(engine, engine_version):
    if engine == "aurora-mysql":
        match = re.match(r"^(\d+\.\d+).+", engine_version)
        if match:
            version_number = match.group(1)
            version_number = version_number.split(".")[0]
        else:
            version_number = None
    elif engine == "aurora-postgresql":
        version_number = engine_version.split(".")[0]
    elif engine == "mysql":
        version_number = engine_version.split(".")[0]
    elif engine == "postgres":
        version_number = engine_version.split(".")[0]
    else:
        logging.info("Not a valid engine input")
        return None

    if version_number is None:
        logging.warning("Version number not found")
        return None

    engine_family = version_number

    default_param_group_mapping = {
        "postgres": f"pg-default-{engine_family}-instance",
        "aurora-postgresql": f"pg-default-{engine_family}-cluster",
        "mysql": f"mysql-default-{engine_family}-instance",
        "aurora-mysql": f"mysql-default-{engine_family}-cluster",
    }
    if engine and engine in default_param_group_mapping:
        default_parameter_group = default_param_group_mapping[engine]
        return default_parameter_group


# Deploy the aurora cluster
def deploy_cluster(
    rds,
    env,
    dbname,
    service,
    cluster_pg_name,
    subnet_group,
    security_group_id,
    engine,
    engine_version,
    password,
    kms_key_id,
    logs,
    region,
    tags,
):
    # We do not need the service itself to show legacy. It is used to identify what account we are deploying to
    cluster_identifier = service + "-" + env + "-cluster"
    try:
        logging.info("Checking if cluster already exists..")
        rds.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
    except rds.exceptions.DBClusterNotFoundFault:
        logging.warning(
            f"The cluster, {cluster_identifier}, does not exist! Creating now....."
        )
        try:
            logging.info("Cluster does not exist. Creating now...")
            rds.create_db_cluster(
                DatabaseName=dbname,
                DBClusterIdentifier=cluster_identifier,
                DBClusterParameterGroupName=cluster_pg_name,
                VpcSecurityGroupIds=[security_group_id],
                DBSubnetGroupName=subnet_group,
                Engine=engine,
                EngineVersion=engine_version,
                MasterUsername="randoneering",
                MasterUserPassword=password,
                Tags=tags,
                StorageEncrypted=True,
                KmsKeyId=kms_key_id,
                EnableCloudwatchLogsExports=logs,
                EngineMode="provisioned",
                DeletionProtection=True,
                CopyTagsToSnapshot=True,
                AutoMinorVersionUpgrade=True,
                DatabaseInsightsMode="standard",
                EnablePerformanceInsights=True,
                ManageMasterUserPassword=False,
                SourceRegion=region,
            )

            # The writer/reader endpoints will not be finalized until the cluster is available.
            logging.info("Waiting for rds cluster availability....")
            waiter = rds.get_waiter("db_cluster_available")
            waiter.wait(DBClusterIdentifier=cluster_identifier)

            logging.info("Checking status of cluster...")
            db_cluster_status = rds.describe_db_clusters(
                DBClusterIdentifier=cluster_identifier
            )
            # Once available, we can grab the actual writer/reader endpoints
            if db_cluster_status["DBClusters"][0]["Status"] == "available":
                logging.info("Getting endpoint information...")
                writer_endpoint = db_cluster_status["DBClusters"][0]["Endpoint"]
                reader_endpoint = db_cluster_status["DBClusters"][0]["ReaderEndpoint"]

                return writer_endpoint, reader_endpoint, cluster_identifier

        except Exception as e:
            logging.error(f"Error creating rds cluster!: {e}")
            raise
    else:
        try:
            logging.warning(
                f"The cluster, {cluster_identifier}, already exists! skipping creation"
            )
            read_cluster = rds.describe_db_clusters(
                DBClusterIdentifier=cluster_identifier
            )
            writer_endpoint = read_cluster["DBClusters"][0]["Endpoint"]
            reader_endpoint = read_cluster["DBClusters"][0]["ReaderEndpoint"]
            return writer_endpoint, reader_endpoint, cluster_identifier

        except Exception as e:
            logging.error(f"Error reading cluster details!: {e}")
            raise


# Deploy the rds instance
def deploy_instance(
    rds,
    env,
    dbname,
    service,
    subnet_group,
    security_group_id,
    engine,
    engine_version,
    password,
    kms_key_id,
    logs,
    instance_class,
    tags,
    instance_pg_name=None,
    cluster_identifier=None,
    storage=None,
    storage_type=None,
):
    count = 1  # eventually, we can add logic to add more instances to clusters in the future
    if engine.startswith("aurora-"):
        instance_identifier = service + f"-instance-{count}"
        try:
            logging.info("Checking if cluster instance already exists..")
            rds.describe_db_instances(DBInstanceIdentifier=instance_identifier)
        except rds.exceptions.DBInstanceNotFoundFault:
            try:
                logging.warning(
                    f"The instance, {instance_identifier}, does not exist! Creating now....."
                )
                rds.create_db_instance(
                    DBClusterIdentifier=cluster_identifier,
                    DBInstanceIdentifier=instance_identifier,
                    DBInstanceClass=instance_class,
                    Engine=engine,
                    EngineVersion=engine_version,
                    Tags=tags,
                    CACertificateIdentifier="rds-ca-ecc384-g1",
                )
                count = +1  # saving for later
                return instance_identifier

            except Exception as e:
                logging.error(f"Error creating rds cluster instance!: {e}")
                raise
        else:
            logging.warning(
                f"The instance, {instance_identifier}, already exists! skipping creation"
            )
            return instance_identifier

    else:
        instance_identifier = service + "-instance"
        try:
            logging.info("Checking if cluster instance already exists..")
            rds.describe_db_instances(DBInstanceIdentifier=instance_identifier)
        except rds.exceptions.DBInstanceNotFoundFault:
            try:
                logging.warning(
                    f"The instance, {instance_identifier}, does not exist! Creating now....."
                )
                rds.create_db_instance(
                    DBInstanceIdentifier=service + "-" + env + "-instance",
                    DBName=dbname,
                    VpcSecurityGroupIds=[security_group_id],
                    DBSubnetGroupName=subnet_group,
                    DBParameterGroupName=instance_pg_name,
                    DBInstanceClass=instance_class,
                    Engine=engine,
                    EngineVersion=engine_version,
                    MasterUsername="randoneering",
                    MasterUserPassword=password,
                    DeletionProtection=True,
                    Tags=tags,
                    AllocatedStorage=storage,
                    StorageType=storage_type,
                    StorageEncrypted=True,
                    KmsKeyId=kms_key_id,
                    EnableCloudwatchLogsExports=logs,
                    CopyTagsToSnapshot=True,
                    AutoMinorVersionUpgrade=True,
                    DatabaseInsightsMode="standard",
                    EnablePerformanceInsights=True,
                    ManageMasterUserPassword=False,
                    CACertificateIdentifier="rds-ca-ecc384-g1",
                )

                logging.info("Waiting for rds instance availability....")
                waiter = rds.get_waiter("db_instance_available")
                waiter.wait(DBInstanceIdentifier=instance_identifier)

                logging.info("Checking status of instance...")
                db_instance_status = rds.describe_db_instances(
                    DBInstanceIdentifier=instance_identifier
                )

                if (
                    db_instance_status["DBInstances"][0]["DBInstanceStatus"]
                    == "available"
                ):
                    logging.info("Getting endpoint information...")
                    writer_endpoint = db_instance_status["DBInstances"][0]["Endpoint"][
                        "Address"
                    ]
                    return instance_identifier, writer_endpoint

            except Exception as e:
                logging.error(f"Error creating rds instance!: {e}")
                raise
        else:
            try:
                logging.warning(
                    f"The instance, {instance_identifier}, already exists! skipping creation"
                )
                read_instance = rds.describe_db_instances(
                    DBInstanceIdentifier=instance_identifier
                )
                writer_endpoint = read_instance["DBInstances"][0]["Endpoint"]["Address"]
                return instance_identifier, writer_endpoint

            except Exception as e:
                logging.error(f"Error creating rds instance!: {e}")
                raise


# Generate the new cluster parameter group from the default parameter group or use an existing group
def deploy_cluster_pg(rds, service, env, default_parameter_group, tags):
    description = f"Cluster parameter group for {env} {service}"
    target_parameter_group = f"{service}-{env}-ClusterParamGroup"
    logging.info(f"Creating cluster parameter group for {env} {service}")
    try:
        rds.describe_db_cluster_parameter_groups(
            DBClusterParameterGroupName=target_parameter_group
        )

    except rds.exceptions.DBParameterGroupNotFoundFault:
        logging.info("Target Parameter Group doesn't exists, creating it!")
        cluster_parameter_group = rds.copy_db_cluster_parameter_group(
            SourceDBClusterParameterGroupIdentifier=default_parameter_group,
            TargetDBClusterParameterGroupIdentifier=target_parameter_group,
            TargetDBClusterParameterGroupDescription=description,
            Tags=tags,
        )
        cluster_pg_name = cluster_parameter_group["DBClusterParameterGroup"][
            "DBClusterParameterGroupName"
        ]

        return cluster_pg_name

    else:
        cluster_pg_name = target_parameter_group
        logging.info(
            f"Cluster parameter group {cluster_pg_name} already exists. Skipping copy."
        )
        return cluster_pg_name


# Generate the new instance parameter group from the default parameter group or use an existing group
def deploy_instance_pg(rds, service, env, default_parameter_group, tags):
    description = f"Instance parameter group for {env} {service}"
    target_parameter_group = f"{service}-{env}-InstanceParamGroup"
    logging.info(f"Creating instance parameter group for {env} {service}")
    try:
        rds.describe_db_parameter_groups(DBParameterGroupName=target_parameter_group)

    except rds.exceptions.DBParameterGroupNotFoundFault:
        logging.warning("Target parameter group does not exist. Creating it!")
        instance_parameter_group = rds.copy_db_parameter_group(
            SourceDBParameterGroupIdentifier=default_parameter_group,
            TargetDBParameterGroupIdentifier=target_parameter_group,
            TargetDBParameterGroupDescription=description,
            Tags=tags,
        )
        instance_pg_name = instance_parameter_group["DBParameterGroup"][
            "DBParameterGroupName"
        ]
        return instance_pg_name

    else:
        instance_pg_name = target_parameter_group
        logging.info(
            f"Instance parameter group {instance_pg_name} already exists. Skipping copy."
        )
        return instance_pg_name


# Generate the kms key for the target resource
def deploy_kms_key(kms, account, region, env, service, tags):
    # KMS tags are "TagKey" where RDS tags are "Key"
    modified_tags = []
    for tag in tags:
        modified_tag = {"TagKey": tag["Key"], "TagValue": tag["Value"]}
        modified_tags.append(modified_tag)

    description = f"KMS key for {env} {service}."
    logging.info(f"Creating kms key for {env} {service}")

    try:
        kms_key = kms.create_key(
            Description=description,
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Tags=modified_tags,
            MultiRegion=False,
        )
        kms_key_id = kms_key["KeyMetadata"]["KeyId"]
    except Exception as e:
        logging.error(f"Error creating KMS key: {e}")
        raise

    # Roles are hardcoded for now-can change this later if you want
    dba_iam_role = "{dba_iam_role}"
    policy = {
        "Id": "dba-kms-grant-policy",
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": f"arn:aws:kms:{region}:{account}:key/{kms_key_id}",
            },
            {
                "Sid": "Allow access for Key Administrators",
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account}:role/{dba_iam_role}"]},
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion",
                ],
                "Resource": f"arn:aws:kms:{region}:{account}:key/{kms_key_id}",
            },
            {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account}:role/{dba_iam_role}"]},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                "Resource": f"arn:aws:kms:{region}:{account}:key/{kms_key_id}",
            },
            {
                "Sid": "Allow attachment of persistent resources",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        f"arn:aws:iam::{account}:role/{dba_iam_role}",
                    ]
                },
                "Action": [
                    "kms:CreateGrant*",
                    "kms:ListGrants*",
                    "kms:RevokeGrant*",
                ],
                "Resource": f"arn:aws:kms:{region}:{account}:key/{kms_key_id}",
                "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}},
            },
        ],
    }

    default_alias = f"alias/{env}-{service}-key"

    try:
        logging.info("Creating alias for kms key")
        kms.create_alias(AliasName=default_alias, TargetKeyId=kms_key_id)

    except kms.exceptions.AlreadyExistsException:
        alias_name = input(
            f"The alias '{default_alias}' already exists. Please provide a custom alias name (eg: alias/.....): "
        )
        kms.create_alias(AliasName=alias_name, TargetKeyId=kms_key_id)

    else:
        logging.info(f"Alias '{default_alias}' created successfully!")

        try:
            policy_json = json.dumps(policy)
            logging.info(f"Creating policy for '{kms_key_id}'")
            kms.put_key_policy(KeyId=kms_key_id, Policy=policy_json)

            logging.info(f"Creating grant for '{kms_key_id}'")
            grantee_principle = f"arn:aws:iam::{account}:role/{dba_iam_role}"
            kms.create_grant(
                KeyId=kms_key_id,
                GranteePrincipal=grantee_principle,
                Operations=["Decrypt", "Encrypt"],
                Name="DBA-KMS-Grant",
            )
            logging.info("kms key created and ready for use!")
        except Exception as e:
            logging.error(f"Error creating/adding policy: {e}")
            raise

    return kms_key_id


# Generate the route53 records. There are no exception warnings that allow us to handle target records that exist, thus the if statements.
def deploy_route53_record(
    route53,
    writer_endpoint,
    hosted_zone_id,
    domain_name,
    reader_endpoint=None,
):
    try:
        writer_dns = f"{service}.{domain_name}"
        writer_record = {
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": writer_dns,
                        "Type": "CNAME",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": f"{writer_endpoint}"}],
                    },
                }
            ]
        }

        # Create Writer Endpoint
        logging.info(f"Checking if {writer_dns} exists...")

        paginator = route53.get_paginator("list_resource_record_sets")
        response_iterator = paginator.paginate(
            HostedZoneId=hosted_zone_id,
        )
        found = False
        for page in response_iterator:
            for record in page["ResourceRecordSets"]:
                if record["Name"] == writer_dns:
                    logging.warning(f"{writer_dns} already exists!")
                    found = True
                    break
            if found:
                break
        if not found:
            try:
                logging.info(f"Creating Writer DNS Endpoint for {writer_endpoint}")

                route53.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id, ChangeBatch=writer_record
                )
                logging.info(f"{writer_dns} created!")
            except Exception as e:
                logging.error(f"Failed to create {writer_dns}: {e}")
        found = False
        if reader_endpoint is not None:
            reader_dns = f"{service}-ro.{domain_name}"
            logging.info(f"Checking if {reader_dns} exists...")
            reader_record = {
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": reader_dns,
                            "Type": "CNAME",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": f"{reader_endpoint}"}],
                        },
                    }
                ]
            }
            for page in response_iterator:
                for record in page["ResourceRecordSets"]:
                    if record["Name"] == reader_dns:
                        logging.warning(f"{reader_dns} already exists!")
                        found = True
                        break
                if found:
                    break
            if not found:
                try:
                    logging.info(f"Creating Reader DNS Endpoint for {reader_endpoint}")
                    route53.change_resource_record_sets(
                        HostedZoneId=hosted_zone_id, ChangeBatch=reader_record
                    )
                    logging.info(f"{reader_dns} created!")
                    return writer_dns, reader_dns
                except Exception as e:
                    logging.error(f"Failed to create {reader_dns}: {e}")

            logging.info(f"""
                Created DNS Entries!:
                Writer Endpoint: {writer_dns}
                Reader Endpoint: {reader_dns}""")
        else:
            logging.info("Reader endpoint not required, skipping creation....")
            logging.info(f"""
                Created DNS Entries!:
                Writer Endpoint: {writer_dns}""")
    except Exception as e:
        logging.error(f"Error creating route53 entries!: {e}")
        raise


# Grab existing security groups for resource deployment
def read_security_group(ec2, security_group, vpc):
    try:
        # Declairing filters
        filters = [
            {"Name": "group-name", "Values": [security_group]},
            {"Name": "vpc-id", "Values": [vpc]},
        ]

        logging.info(f"Searching for security group {security_group} in {vpc}")

        # Grab security group ID
        paginator = ec2.get_paginator("describe_security_groups")
        response_iterator = paginator.paginate(Filters=filters)
        for page in response_iterator:
            for sg in page["SecurityGroups"]:
                if sg["GroupName"] == security_group and sg["VpcId"] == vpc:
                    logging.info(
                        f"Found SG '{security_group}' (ID={sg['GroupId']}) in VPC {vpc}"
                    )
                    return sg["GroupId"]
        logging.warning(f"Security group '{security_group}' not found in VPC {vpc}")
        return None

    except Exception as e:
        logging.error(f"Error reading Security Group ID!: {e}")
        raise


# Main execution
if __name__ == "__main__":
    try:
        # enable logging
        enable_logging()
        # Get User Inputs to fuel the rest of the script
        (
            dbname,
            service,
            engine,
            engine_version,
            env,
            instance_class,
            account,
            tags,
            security_group,
            subnet_group,
            logs,
            region,
            hosted_zone_id,
            vpc,
            domain_name,
            storage,
            storage_type,
        ) = define_request()

        # Get AWS Credentials based on IAM Role
        aws_access_key_id, aws_secret_access_key, aws_session_token, region = (
            aws_credentials(region, account)
        )

        # Generate RDS client
        rds = rds_client(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Generate KMS client
        kms = kms_client(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Generate Route53 client
        route53 = route53_client(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Generate EC2 client
        ec2 = ec2_client(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Generate the correct default parameter group
        default_parameter_group = default_param_group(engine, engine_version)

        # Read Security Group for IDs

        security_group_id = read_security_group(ec2, security_group, vpc)

        # Generate random password for master user/randoneering user for deployment
        password = random_password()

        # Deploy KMS key
        kms_key_id = deploy_kms_key(kms, account, region, env, service, tags)

        # Determine if instance parameter group is needed
        if engine.startswith("aurora-"):
            # Deploy cluster parameter group
            cluster_pg_name = deploy_cluster_pg(
                rds, service, env, default_parameter_group, tags
            )

            # Deploy Cluster
            writer_endpoint, reader_endpoint, cluster_identifier = deploy_cluster(
                rds,
                env,
                dbname,
                service,
                cluster_pg_name,
                subnet_group,
                security_group_id,
                engine,
                engine_version,
                password,
                kms_key_id,
                logs,
                region,
                tags,
            )

            # Set instance_pg_name to None, not needed
            instance_pg_name = None
            instance_identifier = deploy_instance(
                rds,
                env,
                dbname,
                service,
                subnet_group,
                security_group_id,
                engine,
                engine_version,
                password,
                kms_key_id,
                logs,
                instance_class,
                tags,
                instance_pg_name,
                cluster_identifier,
                storage,
                storage_type,
            )

            # Create Route53 Records for Aurora Cluster (write and read)
            writer_dns, reader_dns = deploy_route53_record(
                route53, writer_endpoint, hosted_zone_id, domain_name, reader_endpoint
            )

            logging.info(f"""
                Deployment Successful.
                Cluster Identifier: {cluster_identifier}
                Instance Identifier: {instance_identifier}
                Writer DNS: {writer_dns}
                Reader DNS: {reader_dns}
            """)
        else:
            # Deploy instance parameter group
            instance_pg_name = deploy_instance_pg(
                rds, service, env, default_parameter_group, tags
            )

            # Set cluster_identifier to None as it is not needed
            cluster_identifier = None
            instance_identifier, writer_endpoint = deploy_instance(
                rds,
                env,
                dbname,
                service,
                subnet_group,
                security_group_id,
                engine,
                engine_version,
                password,
                kms_key_id,
                logs,
                instance_class,
                tags,
                instance_pg_name,
                cluster_identifier,
                storage,
                storage_type,
            )
            # Create Route53 Records

            # Set reader endpoint to None as it is not needed
            reader_endpoint = None
            writer_dns = deploy_route53_record(
                route53, writer_endpoint, hosted_zone_id, domain_name
            )

            logging.info(f"""
                Deployment Successful.
                Instance Identifier: {instance_identifier}
                Writer DNS: {writer_dns}
                """)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
