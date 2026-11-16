output "load_balancer_dns_name" {
  description = "Point proxy_url's name here, when route53_zone_id is empty."
  value       = aws_lb.main.dns_name
}

output "cluster" {
  description = "The ECS cluster."
  value       = aws_ecs_cluster.main.name
}

output "refresh_now" {
  description = "Runs `byrle refresh` once, as the schedule does."
  value = join(" ", [
    "aws ecs run-task --region ${var.region} --cluster ${aws_ecs_cluster.main.name}",
    "--task-definition ${aws_ecs_task_definition.refresh.family} --launch-type FARGATE",
    "--network-configuration 'awsvpcConfiguration={subnets=[${join(",", local.network.subnets)}],securityGroups=[${aws_security_group.proxy.id}],assignPublicIp=ENABLED}'",
  ])
}

output "log_group" {
  description = "Every container's output."
  value       = aws_cloudwatch_log_group.main.name
}
