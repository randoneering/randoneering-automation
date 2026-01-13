# Randoneering Database Automation

Automates the provisioning and management of AWS RDS and Aurora databases. This toolkit handles Infrastructure-as-Code automation and database administration for PostgreSQL and MySQL in AWS environments.

## Overview

This project automates:
- Provisioning RDS instances and Aurora clusters
- Initializing databases with role-based access control
- Monitoring connection events and performance metrics
- Managing database users and permissions
- Enforcing DBA security standards across your database fleet

## Features

### Database Provisioning
- Interactive CLI for creating RDS instances and Aurora clusters
- Automated KMS encryption key creation and management
- CloudWatch logging and Performance Insights configuration
- Route53 DNS entry creation (writer and reader endpoints)
- Deletion protection and automated backup configuration
- Support for PostgreSQL, MySQL, Aurora-PostgreSQL, and Aurora-MySQL

### Security & Compliance
- KMS encryption for data at rest
- IAM role-based credential management
- Role-based access control (readonly, readwrite, dba)
- VPC security group isolation
- Deletion protection enforcement
- Audit logging via CloudWatch

### Monitoring
- Database Insights and Performance Insights enablement
- Connection event logging to PostgreSQL database
- CloudWatch log aggregation
- Teams notification integration for errors
- 7-day log retention with automatic cleanup

### Database Administration
- Automated database initialization with schemas and roles
- User provisioning and management
- DBA standards enforcement across database fleet
- Temporary production user management
- S3 integration for backups and exports

## Project Structure

```
randoneering-automation/
├── python/                           # Python automation scripts
│   ├── database_provisioning/        # Main provisioning module
│   ├── aws/                          # AWS-specific utilities
│   ├── remove_tags.py                # Resource tag management
│   └── db_init_pg.sql                # PostgreSQL initialization template
│
└── ansible-playbook/tower/           # Ansible Tower (AWX) playbooks
    ├── db_instance_check.yml         # DBA standards enforcement
    ├── db_init_postgres.yml          # PostgreSQL initialization
    ├── db_init_mysql.yml             # MySQL initialization
    ├── db_create_user.yml            # User provisioning
    └── [additional playbooks]
```

## Technology Stack

- **Python 3** - Automation scripting
- **Ansible** - Configuration management
- **AWS Services** - RDS, Aurora, CloudWatch, Route53, KMS, IAM
- **Databases** - PostgreSQL, MySQL, Aurora variants
- **Orchestration** - Ansible Tower (AWX)

## Getting Started

### Prerequisites

- Python 3.x
- AWS CLI configured with appropriate credentials
- Ansible 2.9+ (for playbook execution)
- Access to Ansible Tower (for production deployment)

### Python Dependencies

Each Python module has its own `requirements.txt`:

```bash
# Database provisioning
cd python/database_provisioning
pip install -r requirements.txt

# Database Insights initialization
cd python/aws/aws_database_insights_init_2025
pip install -r requirements.txt
```

### Ansible Dependencies

```bash
ansible-galaxy collection install amazon.aws
ansible-galaxy collection install community.postgresql
ansible-galaxy collection install community.mysql
```

## Usage

### 1. Provision a New Database

Run the interactive provisioning script:

```bash
cd python/database_provisioning
python database_provisioning.py
```

The script will prompt you to select:
- Environment (e.g., prod)
- Database engine (postgres, mysql, aurora-postgresql, aurora-mysql)
- Engine version
- Instance class (t4g, r7g variants)

The script will:
1. Create KMS encryption key with appropriate policies
2. Set up parameter groups from defaults
3. Provision RDS instance or Aurora cluster
4. Configure CloudWatch logging
5. Enable Performance Insights and Database Insights
6. Create Route53 DNS entries
7. Output connection details

### 2. Initialize Database Schema

After provisioning, initialize the database with roles and schemas:

**For PostgreSQL:**
```bash
ansible-playbook ansible-playbook/tower/db_init_postgres.yml \
  -e db_host=your-db-host.example.com \
  -e db_name=your_database \
  -e db_admin_user=postgres \
  -e db_admin_password=your_password
```

**For MySQL:**
```bash
ansible-playbook ansible-playbook/tower/db_init_mysql.yml \
  -e db_host=your-db-host.example.com \
  -e db_name=your_database \
  -e db_admin_user=admin \
  -e db_admin_password=your_password
```

This creates:
- DBA roles with full privileges
- Service user roles (readonly, readwrite)
- Application schemas with proper permissions

### 3. Create Database Users

Create new users with role-based permissions:

```bash
ansible-playbook ansible-playbook/tower/db_create_user.yml \
  -e db_host=your-db-host.example.com \
  -e db_name=your_database \
  -e db_user=app_user \
  -e db_password=secure_password \
  -e db_role=readwrite  # or readonly
```

### 4. Enable Database Insights (Bulk)

Enable Performance Insights on all RDS instances in your account:

```bash
cd python/aws/aws_database_insights_init_2025
python aws_database_insights_init.py
```

### 5. Monitor Connection Events

Set up connection logging (typically run as a scheduled job):

```bash
cd python/aws
python psql_connection_logging.py
```

This will:
- Fetch connection logs from CloudWatch
- Parse login/logout events
- Store events in PostgreSQL
- Send Teams notifications on errors
- Clean up logs older than 7 days

### 6. Enforce DBA Standards

Audit and enforce security standards across your database fleet:

```bash
ansible-playbook ansible-playbook/tower/db_instance_check.yml
```

Checks include:
- Encryption at rest enabled
- Deletion protection enabled
- Backup retention configured
- Performance Insights enabled
- CloudWatch logging active

## Configuration

### Environment Configuration

Edit `python/database_provisioning/config/options.yml` to customize:

```yaml
environments:
  prod:
    aws_account: '123456789012'
    region: 'us-west-2'
    vpc_id: 'vpc-xxxxx'
    db_subnet_group: 'prod-db-subnet-group'
    hosted_zone_id: 'Z1234567890ABC'
    hosted_zone_name: 'example.com'
```

### Database Engines

Supported engines and versions are defined in `options.yml`:
- PostgreSQL: 13.x, 14.x, 15.x, 16.x
- MySQL: 5.7.x, 8.0.x
- Aurora PostgreSQL: 13.x, 14.x, 15.x
- Aurora MySQL: 5.7.x, 8.0.x

### Instance Classes

Available instance classes (configurable per environment):
- **Burstable:** t4g.medium, t4g.large (dev/test)
- **Memory Optimized:** r7g.large, r7g.2xlarge, r7g.4xlarge (production)

## Security Considerations

### KMS Encryption
All databases are created with KMS encryption at rest. The provisioning script:
- Creates a unique KMS key per database
- Sets up key policies with DBA role access
- Enables automatic key rotation

### IAM Roles
The automation uses IAM role assumption for credential management:
- No hardcoded credentials in scripts
- STS temporary credentials with session tokens
- Least privilege access policies

### Role-Based Access Control (RBAC)
Databases are initialized with three permission tiers:
- **readonly:** SELECT privileges only
- **readwrite:** SELECT, INSERT, UPDATE, DELETE
- **dba:** Full administrative privileges

### Network Isolation
All databases are deployed in private VPC subnets with security groups restricting access to authorized sources only.

## Monitoring & Alerting

### CloudWatch Integration
- Connection logs streamed to CloudWatch
- Slow query logging enabled
- Error logs captured and retained

### Performance Insights
- 7-day retention enabled by default
- Automatic metric collection for query performance
- Available in RDS console for analysis

### Database Insights
- Extended monitoring with OS-level metrics
- Visibility into database operations
- Integrated with CloudWatch dashboards

### Teams Notifications
Error events and critical issues are sent to Microsoft Teams channels.

## Common Workflows

### Creating a Production Database

1. **Provision infrastructure:**
   ```bash
   cd python/database_provisioning
   python database_provisioning.py
   # Select: prod → aurora-postgresql → 15.x → r7g.2xlarge
   ```

2. **Initialize database:**
   ```bash
   ansible-playbook ansible-playbook/tower/db_init_postgres.yml \
     -e db_host=prod-db-cluster.example.com
   ```

3. **Create application user:**
   ```bash
   ansible-playbook ansible-playbook/tower/db_create_user.yml \
     -e db_user=app_backend \
     -e db_role=readwrite
   ```

4. **Verify standards:**
   ```bash
   ansible-playbook ansible-playbook/tower/db_instance_check.yml
   ```

### Managing Temporary Production Access

For temporary troubleshooting access:

```bash
ansible-playbook ansible-playbook/tower/db_prod_temp_user.yml \
  -e action=create \
  -e temp_user=ops_user \
  -e duration_hours=4
```

Remove access after maintenance:

```bash
ansible-playbook ansible-playbook/tower/db_prod_temp_user.yml \
  -e action=remove \
  -e temp_user=ops_user
```

### Cleaning Up Resources

Remove tags from resources:

```bash
cd python
python remove_tags.py \
  --resource-type rds \
  --resource-id db-instance-name \
  --tags Environment Cost-Center
```

## Ansible Tower Deployment

This automation is designed for deployment via Ansible Tower (AWX). Playbooks are located in `ansible-playbook/tower/` and expect:

- Credential management via Tower
- Survey variables for interactive input
- Job templates for common workflows
- Scheduled jobs for monitoring tasks

## Troubleshooting

### Database Provisioning Fails

Check:
- AWS credentials are valid and have sufficient permissions
- VPC subnet group exists and has appropriate subnets
- Route53 hosted zone is accessible
- KMS key creation permissions are granted

### Ansible Playbook Errors

Verify:
- Database host is reachable from Ansible control node
- Admin credentials are correct
- Required Ansible collections are installed
- Python dependencies (psycopg2, PyMySQL) are present

### Connection Logging Not Working

Check:
- CloudWatch Logs permissions for RDS
- Connection logging is enabled in parameter group
- Lambda/EC2 instance running the script has IAM permissions
- Target PostgreSQL database is accessible

## Contributing

This is an internal automation project for Randoneering infrastructure. For questions or issues, contact:

**Owner:** justin@randoneering.tech

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Roadmap

Planned enhancements:
- Support for additional database engines (Aurora Serverless, DocumentDB)
- Multi-region replication setup
- Automated backup verification
- Cost optimization recommendations
- Terraform integration for infrastructure state management
- Self-service portal for developers

## Related Documentation

- [AWS RDS Documentation](https://docs.aws.amazon.com/rds/)
- [AWS Aurora Documentation](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/)
- [Ansible AWS Collection](https://docs.ansible.com/ansible/latest/collections/amazon/aws/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [MySQL Documentation](https://dev.mysql.com/doc/)
