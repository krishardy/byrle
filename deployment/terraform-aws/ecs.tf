# One Fargate task runs three containers:
#
# | Container | Image          | Does                                                          |
# |-----------|----------------|---------------------------------------------------------------|
# | config    | nginx, by digest | runs config.sh, then exits                                  |
# | nginx     | nginx, by digest | docs/fronting-tls.md's server block, on port 80              |
# | byrle     | byrle_image    | `byrle daemon` at 127.0.0.1:8080, which the task's containers share |
#
# A second task definition runs `byrle refresh` alone, on refresh_schedule.

locals {
  # The image compose.yaml uses. `make check-deps` reports when its tag has moved.
  nginx_image = "docker.io/library/nginx:1.30-alpine@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a"

  logs = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.main.name
      awslogs-region        = var.region
      awslogs-stream-prefix = var.name
    }
  }

  # var.environment first, so the settings that depend on this layout replace any it repeats.
  byrle_environment = merge(
    var.environment,
    var.mode == "" ? {} : { BYRLE_MODE = var.mode },
    { BYRLE_DATABASE_URL = local.database_url },
  )
  byrle_secrets = concat(
    [{ name = "PGPASSWORD", valueFrom = aws_secretsmanager_secret.db_password.arn }],
    var.github_token_secret_arn == "" ? [] : [
      { name = "BYRLE_GITHUB_TOKEN", valueFrom = var.github_token_secret_arn },
    ],
  )
  secret_arns = compact([
    aws_secretsmanager_secret.db_password.arn,
    aws_secretsmanager_secret.rp_key.arn,
    var.github_token_secret_arn,
  ])

  daemon_environment = merge(local.byrle_environment, {
    BYRLE_LISTEN            = "127.0.0.1:8080"
    BYRLE_PROXY_URL         = var.proxy_url
    BYRLE_POLICY            = "/etc/byrle/policy.yaml"
    BYRLE_SPOOL_DIR         = "/spool/byrle"
    BYRLE_AUDIT_LOG         = "/var/log/byrle/audit.jsonl"
    BYRLE_ACCOUNT_EVENT_LOG = "/var/log/byrle/account-events.jsonl"
  })
  network = {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.proxy.id]
    assign_public_ip = true
  }
}

resource "aws_ecs_cluster" "main" {
  name = var.name
}

resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_task_definition" "daemon" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.architecture
  }

  # The spool holds up to 8 GiB.
  ephemeral_storage {
    size_in_gib = 30
  }

  volume {
    name = "config"
  }

  volume {
    name = "nginx"
  }

  volume {
    name = "spool"
  }

  volume {
    name = "logs"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.logs.id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.logs.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name             = "config"
      image            = local.nginx_image
      essential        = false
      entryPoint       = ["/bin/sh", "-c"]
      command          = [file("${path.module}/config.sh")]
      logConfiguration = local.logs
      environment = [
        { name = "BYRLE_POLICY_YAML", value = file("${path.module}/${var.policy_file}") },
        { name = "BYRLE_NGINX_TEMPLATE", value = file("${path.module}/nginx.conf.template") },
        { name = "BYRLE_VPC_CIDR", value = var.vpc_cidr },
      ]
      secrets = [{ name = "BYRLE_RP_KEY", valueFrom = aws_secretsmanager_secret.rp_key.arn }]
      mountPoints = [
        { sourceVolume = "config", containerPath = "/config" },
        { sourceVolume = "nginx", containerPath = "/nginx" },
        { sourceVolume = "spool", containerPath = "/spool" },
      ]
    },
    {
      name             = "nginx"
      image            = local.nginx_image
      essential        = true
      logConfiguration = local.logs
      portMappings     = [{ containerPort = 80, protocol = "tcp" }]
      dependsOn        = [{ containerName = "config", condition = "SUCCESS" }]
      mountPoints = [
        { sourceVolume = "nginx", containerPath = "/etc/nginx/conf.d", readOnly = true },
      ]
    },
    {
      name             = "byrle"
      image            = var.byrle_image
      essential        = true
      command          = ["daemon"]
      logConfiguration = local.logs
      dependsOn        = [{ containerName = "config", condition = "SUCCESS" }]
      environment      = [for name, value in local.daemon_environment : { name = name, value = value }]
      secrets = concat(local.byrle_secrets, [
        { name = "BYRLE_RP_KEY", valueFrom = aws_secretsmanager_secret.rp_key.arn },
      ])
      mountPoints = [
        { sourceVolume = "config", containerPath = "/etc/byrle", readOnly = true },
        { sourceVolume = "spool", containerPath = "/spool" },
        { sourceVolume = "logs", containerPath = "/var/log/byrle" },
      ]
    },
  ])
}

# One task. Two would append to the same logs on EFS, so a new task starts only once the
# old one has stopped: an apply that changes the task leaves installs unanswered for about a
# minute.
resource "aws_ecs_service" "daemon" {
  name                               = var.name
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.daemon.arn
  launch_type                        = "FARGATE"
  desired_count                      = 1
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  health_check_grace_period_seconds  = 60
  enable_execute_command             = true
  propagate_tags                     = "SERVICE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = local.network.subnets
    security_groups  = local.network.security_groups
    assign_public_ip = local.network.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "nginx"
    container_port   = 80
  }

  depends_on = [aws_lb_listener.https, aws_efs_mount_target.logs]
}

resource "aws_ecs_task_definition" "refresh" {
  family                   = "${var.name}-refresh"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.architecture
  }

  container_definitions = jsonencode([
    {
      name             = "byrle"
      image            = var.byrle_image
      essential        = true
      command          = ["refresh"]
      logConfiguration = local.logs
      environment      = [for name, value in local.byrle_environment : { name = name, value = value }]
      secrets          = local.byrle_secrets
    },
  ])
}

resource "aws_scheduler_schedule" "refresh" {
  name                         = "${var.name}-refresh"
  schedule_expression          = var.refresh_schedule
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 15
  }

  target {
    arn      = aws_ecs_cluster.main.arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.refresh.arn_without_revision
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = local.network.subnets
        security_groups  = local.network.security_groups
        assign_public_ip = local.network.assign_public_ip
      }
    }

    retry_policy {
      maximum_retry_attempts = 0
    }
  }
}
