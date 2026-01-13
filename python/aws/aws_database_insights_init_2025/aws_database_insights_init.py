import argparse
import logging
import sys
import traceback

import boto3
import botocore

# Args
parser = argparse.ArgumentParser(description="AWS Database Insights Initialization")
parser.add_argument("-a", "--account", required=True, help="account #")
parser.add_argument("-r", "--region", required=True, help="target region")


# Initialize logging
def enable_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


# Get AWS credentials from IAM role to make api calls
def aws_credentials(region, account):
    role_arn = f"arn:aws:iam::{account}:role/yourrole"
    try:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="aws_database_insights_init",
        )["Credentials"]
        region = region
        aws_access_key_id = creds["AccessKeyId"]
        aws_secret_access_key = creds["SecretAccessKey"]
        aws_session_token = creds["SessionToken"]
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to initialize aws credentials: {e}")
        sys.exit(1)
    return aws_access_key_id, aws_secret_access_key, aws_session_token, region


# Generate RDS client
def rds_client(aws_access_key_id, aws_secret_access_key, aws_session_token, region):
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region,
    )
    rds = session.client("rds")

    return rds


# Build connection lists of instances and clusters
def connection_list(rds):
    # Get clusters
    postgres_instances = []
    postgres_clusters = []
    mysql_clusters = []
    mysql_instances = []

    try:
        # Get clusters
        paginator_cluster = rds.get_paginator("describe_db_clusters")
        for page in paginator_cluster.paginate():
            for cluster in page["DBClusters"]:
                engine = cluster["Engine"].lower()
                if engine == "postgres" or engine == "aurora-postgresql":
                    postgres_clusters.append(cluster)
                elif engine == "mysql" or engine == "aurora-mysql":
                    mysql_clusters.append(cluster)

        # Get instances
        paginator_instance = rds.get_paginator("describe_db_instances")
        for page in paginator_instance.paginate():
            for instance in page["DBInstances"]:
                engine = instance["Engine"].lower()
                if engine == "postgres":
                    postgres_instances.append(instance)
                elif engine == "mysql":
                    mysql_instances.append(instance)

        # Build list of clusters, only grabbing the identifier
        postgres_clusters_list = [
            (cluster["DBClusterIdentifier"]) for cluster in postgres_clusters
        ]
        # Build list of instances, only grabbing the identifier
        postgres_instances_list = [
            (instance["DBInstanceIdentifier"]) for instance in postgres_instances
        ]

        # Build list of instances, only grabbing the identifier
        mysql_clusters_list = [
            (cluster["DBClusterIdentifier"]) for cluster in mysql_clusters
        ]

        # Build list of instances, only grabbing the identifier
        mysql_instances_list = [
            (instance["DBInstanceIdentifier"]) for instance in mysql_instances
        ]

        # Combine both lists together
        clusters_list = mysql_clusters_list + postgres_clusters_list
        instances_list = mysql_instances_list + postgres_instances_list

        logging.info(
            f"Found {len(postgres_clusters)} clusters and {len(postgres_instances)} instances."
        )
        logging.info(
            f"Found {len(mysql_clusters)} clusters and {len(mysql_instances)} instances."
        )
        return clusters_list, instances_list

    except botocore.exceptions.ClientError as e:
        logging.error(f"Error fetching RDS clusters/instances: {e}")
        sys.exit(1)


def apply_rds_setting(rds, clusters_list, instances_list):
    try:
        # Apply to Clusters
        logging.info("Looping through clusters")
        for cluster in clusters_list:
            logging.info(f"Modifying {cluster}")
            rds.modify_db_cluster(
                DBClusterIdentifier=cluster,
                ApplyImmediately=True,
                DatabaseInsightsMode="standard",
                EnablePerformanceInsights=True,
                PerformanceInsightsRetentionPeriod=7,
            )

        # Apply to Instances
        logging.info("Looping through instances")
        for instance in instances_list:
            logging.info(f"Modifying {instance}")
            rds.modify_db_instance(
                DBInstanceIdentifier=instance,
                ApplyImmediately=True,
                DatabaseInsightsMode="standard",
                EnablePerformanceInsights=True,
                PerformanceInsightsRetentionPeriod=7,
            )

    except botocore.exceptions.ClientError as e:
        logging.error(f"Error applying settings to instances/clusters: {e}")
        sys.exit(1)


# Main execution
if __name__ == "__main__":
    # Args
    args = parser.parse_args()
    account = args.account
    region = args.region

    # Enable logging
    enable_logging()

    try:
        # Get AWS Credentials based on IAM Role
        aws_access_key_id, aws_secret_access_key, aws_session_token, region = (
            aws_credentials(region, account)
        )

        # Generate RDS client
        rds = rds_client(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Get List of RDS Clusters and Instances
        clusters_list, instances_list = connection_list(rds)

        # Apply target rds setting
        apply_rds_setting(rds, clusters_list, instances_list)

        logging.info("""
            Clusters and instances have been adjusted to use Database Insights
        """)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")

    except botocore.exceptions.ClientError as e:
        logging.error(f"Unexpected error in boto3/botocore execution: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in main execution: {e}")
        logging.error(f"Traceback error: {e}\n{traceback.format_exc()}")
