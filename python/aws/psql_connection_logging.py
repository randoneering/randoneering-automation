import argparse
import datetime
import inspect
import logging
import os
import re
import sys
import time
import traceback
from contextlib import redirect_stdout
from datetime import timedelta, timezone
from io import StringIO
from time import strftime

import arrow
import boto3
import botocore
import psycopg2
from cryptography.fernet import Fernet
from psycopg2 import OperationalError, connect, errorcodes, errors, sql  #
from requests import post

# Static Args
role_arn = ""
encrypt_key = ""
encrypted_password = ""  # change
webhook = ""
alert = "The psql_connection_logging service experienced an error."
alert_message = "Please check the most recent log for details in '/mnt/logs' or run 'sudo journalctl -f pg-con-logging.service'"


def clean_old_logs():
    # Clean up logs older than 7 days before creating a new log.
    log_folder = "/mnt/logs/"
    try:
        seven_days_ago = datetime.datetime.now(timezone.utc) - timedelta(days=7)
        for logname in os.listdir(log_folder):
            log_path = os.path.join(log_folder, logname)
            if os.path.isfile(log_path):
                file_modified_time = datetime.datetime.fromtimestamp(
                    os.path.getmtime(log_path), timezone.utc
                )
                if file_modified_time < seven_days_ago:
                    print(f"Deleting old log file: {log_path}")
                    os.remove(log_path)
                else:
                    print(f"Keeping recent log file: {log_path}")
            else:
                print(f"Skipped: {log_path} (not a file)")
    except Exception as e:
        print(f"Error during log cleanup: {e}")


def enable_logging():
    # Initialize logging
    log_file = "/mnt/logs/" + datetime.datetime.now().strftime(
        "psql_connection_logging_%Y_%m_%d_%H_%M.log"
    )

    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def decrypt_dbpass(encrypt_key, encrypted_password):
    # Read the Fernet key from the file
    try:
        with open(encrypt_key, "r") as key_file:
            fernet_key = key_file.read().strip()
    except Exception as e:
        raise FileNotFoundError(
            f"Failed to read encryption key from {encrypt_key}: {e}"
        )

    # Read the encrypted password from the file
    try:
        with open(encrypted_password, "rb") as pass_file:
            encrypted_data = pass_file.read()
    except Exception as e:
        raise FileNotFoundError(
            f"Failed to read encrypted password from {encrypted_password}: {e}"
        )

    # Decrypt the password
    try:
        fernet = Fernet(fernet_key.encode())  # Ensure the key is encoded as bytes
        decrypted_password = fernet.decrypt(encrypted_data).decode()
        return decrypted_password
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")


# Get AWS credentials from IAM role to make api calls
def aws_credentials(role_arn):
    try:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="postgres_connection_logging",
        )["Credentials"]
        region = "us-east-1"
        aws_access_key_id = creds["AccessKeyId"]
        aws_secret_access_key = creds["SecretAccessKey"]
        aws_session_token = creds["SessionToken"]
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to initialize aws credentials: {e}")
        sys.exit(1)
    return aws_access_key_id, aws_secret_access_key, aws_session_token, region


# Simple function to get current UTC time for logging table in atlas
def get_utc():
    try:
        now_utc = datetime.datetime.now(timezone.utc)
        # Create end of current day in UTC
        end_of_current_day = now_utc.replace(
            hour=23, minute=59, second=59, microsecond=999999
        )
        end_of_previous_day = end_of_current_day - timedelta(days=1)
        startTime = int(end_of_previous_day.timestamp() * 1000)
        endTime = int(end_of_current_day.timestamp() * 1000)
        logging.info(f"End of current day (epoch): {endTime}")
        logging.info(f"End of previous day (epoch): {startTime}")
    except Exception as e:
        logging.error(f"Error calculating time range: {e}")
        sys.exit(1)

    return startTime, endTime


# Classify the type of events we will record
def classify_event(message):
    """Classify the event based on the message content."""
    if "disconnection" in message:
        return "disconnection_event"
    elif "connection authenticated" in message:
        return "login_event"
    elif "connection authorized" in message:
        return "login_event"
    elif "password authentication failed" in message:
        return "failed_login"
    else:
        return None  # No match for known event types


def notify_teams(webhook, alert, alert_message):
    """
    Format of the json payload/message for teams in PowerAutomate
    {
        "type": "object",
        "properties": {
            "alert": {
                "type": "string"
            },
            "alert_message": {
                "type": "string"
            }
        }
    }
    """

    url = webhook
    body = {}
    body["alert"] = alert
    body["alert_message"] = alert_message
    response = post(url, json=body, headers={"Content-Type": "application/json"})
    return response


# Build connection lists of instances and clusters
def connection_list(
    aws_access_key_id, aws_secret_access_key, aws_session_token, region
):
    # Get clusters
    postgres_instances = []
    postgres_clusters = []

    # Initialize RDS Client
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region,
        )
        rds = session.client("rds")
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to create AWS RDS client: {e}")
        sys.exit(1)

    try:
        # Get clusters
        paginator_cluster = rds.get_paginator("describe_db_clusters")
        for page in paginator_cluster.paginate(
            Filters=[{"Name": "engine", "Values": ["postgres", "aurora-postgresql"]}]
        ):
            postgres_clusters.extend(page["DBClusters"])

        # Get instances
        paginator_instance = rds.get_paginator("describe_db_instances")
        for page in paginator_instance.paginate(
            Filters=[{"Name": "engine", "Values": ["postgres"]}]
        ):
            postgres_instances.extend(page["DBInstances"])

        # Build list of clusters, only grabbing the identifier (not endpoint!)
        postgres_clusters_list = [
            (cluster["DBClusterIdentifier"]) for cluster in postgres_clusters
        ]

        # Build list of instances, only grabbing the identifier (not endpoi!)
        postgres_instances_list = [
            (instance["DBInstanceIdentifier"]) for instance in postgres_instances
        ]
        logging.info(
            f"Found {len(postgres_clusters)} clusters and {len(postgres_instances)} instances."
        )
        return postgres_clusters_list, postgres_instances_list
    except botocore.exceptions.ClientError as e:
        logging.error(f"Error fetching RDS clusters/instances: {e}")
        sys.exit(1)


# With list of connections, cycle through clusters and instances to pull log_events
def connection_logging_clusters(
    postgres_clusters_list,
    endTime,
    startTime,
    aws_access_key_id,
    aws_secret_access_key,
    aws_session_token,
    region,
):
    filtered_cluster_logs = []
    excluded_users = [
        "rdsmon",
        "rdsadmin",
        "rdshm",
    ]  # Removes this user(or future list of users) from the filter. "rdsmon" user can be ignore as it is an internal AWS user

    # Mapping for filter patterns to regex patterns for extracting the required fields from postgresql log
    filter_to_regex = {
        "connection authenticated": {"user": r"identity=([^ ]+)"},
        "connection authorized": {"user": r"user=([^ ]+)"},
        "password authentication failed": {
            "user": r"user=([^ ]+)",
            "error": r"error=([^ ]+)",
        },
        "disconnection": {
            "user": r"user=([^ ]+)",
            "host": r"host=([^ ]+)",
        },
    }
    # Initialize Cloudwatch client
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region,
        )
        cloudwatch = session.client("logs")
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to create cloudwatch logs client: {e}")
        sys.exit(1)

    paginator = cloudwatch.get_paginator("filter_log_events")
    # Filter through logs for each cluster
    try:
        for cluster in postgres_clusters_list:
            clusterLogGroupName = "/aws/rds/cluster/" + cluster + "/postgresql"
            logging.debug(f"Processing cluster log group: {clusterLogGroupName}")
            # Based on pattern, filter using the regex command
            for filter_pattern in filter_to_regex:
                try:
                    response_iterator = paginator.paginate(
                        logGroupName=clusterLogGroupName,
                        filterPattern=filter_pattern,
                        startTime=startTime,
                        endTime=endTime,
                    )
                    # For each page of response, grab details from logs
                    for page in response_iterator:
                        for event in page["events"]:
                            message = event.get("message", "")
                            event_type = classify_event(message)
                            timestamp = event.get("timestamp", "")

                            if not timestamp:
                                logging.warning("Missing timestamp in log event.")
                                continue

                            try:
                                utc_time = arrow.get(timestamp).format(
                                    "YYYY-MM-DD HH:mm:ss"
                                )
                                cst_time = (
                                    arrow.get(timestamp)
                                    .to("US/Mountain")  # Change this for your timezone
                                    .format("YYYY-MM-DD HH:mm:ss")
                                )
                            except Exception as e:
                                logging.warning(f"Error converting timestamp: {e}")
                                continue

                            regex_patterns = filter_to_regex[filter_pattern]
                            extracted = {}
                            for field, pattern in regex_patterns.items():
                                match = re.search(pattern, message)
                                if match:
                                    extracted[field] = match.group(1)

                                else:
                                    logging.warning(
                                        f"Failed to extract field '{field}' from message: {message}"
                                    )
                                    extracted[field] = None
                            user = extracted.get("user")
                            user = user.replace('"', "")
                            # if user is None or "":
                            if not user:
                                logging.warning(
                                    f"Skipping entry with empty or null username: {user}"
                                )
                                continue

                            # Exclude users in the excluded_users list from the log pull
                            if user in excluded_users:
                                continue
                            # Ensure all required fields are present
                            else:
                                db_host = cluster
                                host = extracted.get("host")
                                if filter_pattern == "disconnection":
                                    if not host:
                                        logging.warning(
                                            f"Missing 'host' field for user: {user}"
                                        )
                                        continue

                                try:
                                    filtered_cluster_logs.append(
                                        {
                                            "db_host": db_host,
                                            "username": user,
                                            "host": host,
                                            "event_type": event_type,
                                            "timestamp_utc": utc_time,
                                            "timestamp_cst": cst_time,
                                            "error": extracted.get("error", None),
                                        }
                                    )
                                except Exception as e:
                                    logging.error(f"Error appending log entry: {e}")
                                    continue
                except Exception as e:
                    logging.error(
                        f"Error processing log group '{clusterLogGroupName}': {e}"
                    )
                    logging.error(f"Traceback error: {e}\n{traceback.format_exc()}")
                    logging.error(
                        f"Error on line {inspect.currentframe().f_lineno}: {e}"
                    )
                    continue

        logging.info(f"Filtered {len(filtered_cluster_logs)} log entries.")
        return filtered_cluster_logs
    except Exception as e:
        logging.error(f"Error processing logs: {e}\n{traceback.format_exc()}")
        logging.error(f"Error on line {inspect.currentframe().f_lineno}: {e}")
        sys.exit(1)


def connection_logging_instances(
    postgres_instances_list,
    endTime,
    startTime,
    aws_access_key_id,
    aws_secret_access_key,
    aws_session_token,
    region,
):
    filtered_instance_logs = []
    excluded_users = [
        "rdsmon",
        "rdsadmin",
        "rdshm",
    ]  # Removes this user(or future list of users) from the filter. "rdsmon" user can be ignore as it is an internal AWS user

    # Mapping for filter patterns to regex patterns for extracting the required fields from postgresql log
    filter_to_regex = {
        "connection authenticated": {"user": r"identity=([^ ]+)"},
        "connection authorized": {"user": r"user=([^ ]+)"},
        "password authentication failed": {
            "user": r"user=([^ ]+)",
            "error": r"error=([^ ]+)",
        },
        "disconnection": {
            "user": r"user=([^ ]+)",
            "host": r"host=([^ ]+)",
        },
    }
    # Initialize Cloudwatch client
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region,
        )
        cloudwatch = session.client("logs")
    except botocore.exceptions.ClientError as e:
        logging.error(f"Failed to create cloudwatch logs client: {e}")
        sys.exit(1)

    paginator = cloudwatch.get_paginator("filter_log_events")
    # Filter through logs for each cluster
    try:
        for instance in postgres_instances_list:
            instanceLogGroupName = "/aws/rds/instance/" + instance + "/postgresql"
            logging.debug(f"Processing instance log group: {instanceLogGroupName}")
            # Based on pattern, filter using the regex command
            for filter_pattern in filter_to_regex:
                try:
                    response_iterator = paginator.paginate(
                        logGroupName=instanceLogGroupName,
                        filterPattern=filter_pattern,
                        startTime=startTime,
                        endTime=endTime,
                    )
                    # For each page of response, grab details from logs
                    for page in response_iterator:
                        for event in page["events"]:
                            message = event.get("message", "")
                            event_type = classify_event(message)
                            timestamp = event.get("timestamp", "")

                            if not timestamp:
                                logging.warning("Missing timestamp in log event.")
                                continue

                            try:
                                utc_time = arrow.get(timestamp).format(
                                    "YYYY-MM-DD HH:mm:ss"
                                )
                                cst_time = (
                                    arrow.get(timestamp)
                                    .to("US/Mountain")
                                    .format("YYYY-MM-DD HH:mm:ss")
                                )
                            except Exception as e:
                                logging.warning(f"Error converting timestamp: {e}")
                                continue

                            regex_patterns = filter_to_regex[filter_pattern]
                            extracted = {}
                            for field, pattern in regex_patterns.items():
                                match = re.search(pattern, message)
                                if match:
                                    extracted[field] = match.group(1)
                                else:
                                    logging.warning(
                                        f"Failed to extract field '{field}' from message: {message}"
                                    )
                                    extracted[field] = None
                            user = extracted.get("user")
                            user = user.replace('"', "")
                            if not user:
                                logging.warning(
                                    f"Skipping entry with empty or null username: {user}"
                                )
                                continue
                                # Exclude users in the excluded_users list from the log pull
                            # Exclude users in the excluded_users list from the log pull
                            if user in excluded_users:
                                continue
                            else:
                                # Ensure all required fields are present
                                db_host = instance
                                host = extracted.get("host")
                                if filter_pattern == "disconnection":
                                    if not host:
                                        logging.warning(
                                            f"Missing 'host' field for user: {user}"
                                        )
                                        continue

                                try:
                                    filtered_instance_logs.append(
                                        {
                                            "db_host": db_host,
                                            "username": user,
                                            "host": host,
                                            "event_type": event_type,
                                            "timestamp_utc": utc_time,
                                            "timestamp_cst": cst_time,
                                            "error": extracted.get("error", None),
                                        }
                                    )
                                except Exception as e:
                                    logging.error(f"Error appending log entry: {e}")
                                    continue
                except Exception as e:
                    logging.error(
                        f"Error processing log group '{instanceLogGroupName}': {e}"
                    )
                    logging.error(
                        f"Error on line {inspect.currentframe().f_lineno}: {e}"
                    )
                    logging.error(f"Traceback Error: {e}\n{traceback.format_exc()}")
                    continue

        logging.info(f"Filtered {len(filtered_instance_logs)} log entries.")
        return filtered_instance_logs
    except Exception as e:
        logging.error(f"Error processing logs: {e}\n{traceback.format_exc()}")
        logging.error(f"Error on line {inspect.currentframe().f_lineno}: {e}")
        sys.exit(1)


def write_connections_to_table(
    atlas_endpoint, filtered_logs, dbname, in_db_username, in_db_password
):
    # connect to atlas
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            host=atlas_endpoint,
            user=in_db_username,
            password=in_db_password,
        )
        print(f"Connected to {atlas_endpoint}")

        conn.autocommit = False
        cur = conn.cursor()

        # insert lines into connection_logging table
        for line in filtered_logs:
            cur.execute("SAVEPOINT sp_ins")
            try:
                db_host = line.get("db_host")
                user = line.get("username")
                host = line.get("host")
                timestamp_utc = line.get("timestamp_utc")
                timestamp_cst = line.get("timestamp_cst")
                event_type = line.get("event_type")
                error = line.get("error")

                # Ensure that all required fields are present before inserting
                cur.execute(
                    """
                    INSERT INTO application.connection_events
                    (db_host, username, host, event_time_utc, event_time_central, event_type, error)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (username, event_time_utc, event_time_central) DO NOTHING;
                """,
                    (
                        db_host,
                        user,
                        host,
                        timestamp_utc,
                        timestamp_cst,
                        event_type,
                        error,
                    ),
                )
            except Exception as e:
                logging.error(f"Error inserting log entry into database: {e}")
                cur.execute("ROLLBACK TO SAVEPOINT sp_ins")
                continue

        conn.commit()
        cur.close()
        conn.close()
        logging.info("Successfully inserted all log entries.")
    except OperationalError as e:
        logging.error(f"Database connection error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while writing to database: {e}")


# Main execution
if __name__ == "__main__":
    # Args
    parser = argparse.ArgumentParser(description="Postgres Connection Logging")
    parser.add_argument("-H", "--host", required=True, help="Atlas Hostname/IP")
    parser.add_argument("-u", "--username", required=True, help="Database username")
    parser.add_argument("-p", "--password", required=False, help="Database password")
    parser.add_argument("-t", "--target_db", required=True, help="Target database name")
    parser.add_argument("-s", "--schema", required=True, help="Target database schema")

    # Grab arguements passed through
    args = parser.parse_args()
    atlas_endpoint = args.host
    schema = args.schema
    dbname = args.target_db
    db_username = args.username

    try:
        # Clean logs older than 7 days
        clean_old_logs()

        # Initialize new log for this run
        enable_logging()
        logging.info("Starting the script...")

        # Decrypt db password
        decrypted_password = decrypt_dbpass(encrypt_key, encrypted_password)

        # Setup AWS Creds for clients
        aws_access_key_id, aws_secret_access_key, aws_session_token, region = (
            aws_credentials(role_arn)
        )

        # Get UTC time
        startTime, endTime = get_utc()

        # Fetch clusters and instances
        postgres_clusters_list, postgres_instances_list = connection_list(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Filter logs
        filtered_cluster_logs = connection_logging_clusters(
            postgres_clusters_list,
            endTime,
            startTime,
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
            region,
        )
        filtered_instance_logs = connection_logging_instances(
            postgres_instances_list,
            endTime,
            startTime,
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
            region,
        )

        filtered_logs = filtered_cluster_logs + filtered_instance_logs

        # Write to database
        if filtered_logs:
            write_connections_to_table(
                atlas_endpoint, filtered_logs, dbname, db_username, decrypted_password
            )
        else:
            logging.info("No log entries to insert into the database.")
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")

    except botocore.exceptions.ClientError as e:
        logging.error(f"Unexpected error in boto3/botocore execution: {e}")
        response = notify_teams(webhook, alert, alert_message)
    except Exception as e:
        logging.error(f"Traceback error: {e}\n{traceback.format_exc()}")
        logging.error(f"Error on line {inspect.currentframe().f_lineno}: {e}")
        logging.error(f"Unexpected error in main execution: {e}")
        response = notify_teams(webhook, alert, alert_message)
