# RDS Postgres in the private subnets. The password is generated on each run, and sent to RDS
# and Secrets Manager only when db_password_version changes, so it is in neither the plan nor
# the state. The tasks read it from Secrets Manager as PGPASSWORD: BYRLE_DATABASE_URL has
# no password, and sqlx reads PGPASSWORD then.

ephemeral "random_password" "db" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "db_password" {
  name_prefix = "${var.name}-db-password-"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id                = aws_secretsmanager_secret.db_password.id
  secret_string_wo         = ephemeral.random_password.db.result
  secret_string_wo_version = var.db_password_version
}

resource "aws_db_subnet_group" "main" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "main" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  db_name             = "byrle"
  username            = "byrle"
  password_wo         = ephemeral.random_password.db.result
  password_wo_version = var.db_password_version

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  multi_az               = var.db_multi_az

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
  deletion_protection        = var.deletion_protection
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${var.name}-final"
}

locals {
  # RDS for Postgres 15 and later refuses unencrypted connections. `require` encrypts without
  # checking the server's certificate: the release image has no RDS certificate authority
  # for `verify-full` to check it against.
  database_url = "postgres://byrle@${aws_db_instance.main.address}:${aws_db_instance.main.port}/byrle?sslmode=require"
}
