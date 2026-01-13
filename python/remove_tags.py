import logging

import boto3
import botocore
from botocore import exceptions

profile = input(f"enter aws profile/alias: ")
region = "us-east-1"

# Create RDS client
rds_session = boto3.Session(profile_name=profile, region_name=region)
rds = rds_session.client("rds")

# Create DocDB client
docdb_session = boto3.Session(profile_name=profile, region_name=region)
docdb = docdb_session.client("docdb")

# Create DynamoDB client
dynamodb_session = boto3.Session(profile_name=profile, region_name=region)
dynamodb = dynamodb_session.client("dynamodb")


def remove_backup_tag():
    # # RDS
    paginator = rds.get_paginator(
        "describe_db_instances"
    )  # grab rds instances in account
    page_iterator = paginator.paginate()
    filtered_iterator = page_iterator.search(
        "DBInstances[].{DBInstanceIdentifier: DBInstanceIdentifier, DBInstanceArn: DBInstanceArn}"
    )  # With the results of the command, fitler out the identifier and the arn
    for page in filtered_iterator:
        DBInstanceArn = page["DBInstanceArn"]  # set variables
        DBInstance = page["DBInstanceIdentifier"]  # set variables
        rds.remove_tags_from_resource(
            ResourceName=DBInstanceArn, TagKeys=["Backup"]
        )  # Remove Backup Tag
        print(f"removing backup tag for:", DBInstance)
    # # Aurora
    paginator = rds.get_paginator(
        "describe_db_clusters"
    )  # Run command to pull a list of resources
    page_iterator = paginator.paginate()  #
    filtered_iterator = page_iterator.search(
        "DBClusters[].{DBClusterIdentifier: DBClusterIdentifier, DBClusterArn: DBClusterArn}"
    )  # With the results of the command, fitler out the identifier and the arn
    for page in filtered_iterator:
        DBClusterArn = page["DBClusterArn"]  # set variables
        DBCluster = page["DBClusterIdentifier"]  # set variables
        rds.remove_tags_from_resource(
            ResourceName=DBClusterArn, TagKeys=["Backup"]
        )  # Remove Backup Tag
        print(f"removing backup tag for:", DBCluster)

    # # DocDB
    paginator = docdb.get_paginator(
        "describe_db_clusters"
    )  # Run command to pull a list of resources
    page_iterator = paginator.paginate()
    filtered_iterator = page_iterator.search(
        "DBClusters[].{DBClusterIdentifier: DBClusterIdentifier, DBClusterArn: DBClusterArn}"
    )  # With the results of the command, fitler out the identifier and the arn
    for page in filtered_iterator:
        DBClusterArn = page["DBClusterArn"]  # set variables
        DBCluster = page["DBClusterIdentifier"]  # set variables
        rds.remove_tags_from_resource(
            ResourceName=DBClusterArn, TagKeys=["Backup"]
        )  # Remove Backup Tag
        print(f"removing backup tag for:", DBCluster)

    # Dynamodb
    paginator = dynamodb.get_paginator("list_tables")
    page_iterator = paginator.paginate()
    filtered_iterator = page_iterator.search(
        "TableNames[]"
    )  # grab all table names in account
    for page in filtered_iterator:
        table_details = dynamodb.describe_table(
            TableName=page
        )  # grab details for target table so we can grab the arn
        table_arn = table_details["Table"]["TableArn"]  # set arn variable
        dynamodb.untag_resource(
            ResourceArn=table_arn, TagKeys=["Backup"]
        )  # Remove Backup Tag
        print(f"removing backup tag for:", page)


if __name__ == "__main__":
    remove_backup_tag()
