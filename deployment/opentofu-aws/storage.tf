# EFS for the audit and account event logs, which outlive a task. The access point makes every
# file 65532's, the release image's user, which has no shell to chown with. The spool is on
# the task's own storage: it holds downloads only while they are analysed.

resource "aws_efs_file_system" "logs" {
  creation_token = "${var.name}-logs"
  encrypted      = true

  tags = { Name = "${var.name}-logs" }
}

resource "aws_efs_backup_policy" "logs" {
  file_system_id = aws_efs_file_system.logs.id

  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_mount_target" "logs" {
  count = length(aws_subnet.private)

  file_system_id  = aws_efs_file_system.logs.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "logs" {
  file_system_id = aws_efs_file_system.logs.id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/byrle"

    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0750"
    }
  }
}
