# The load balancer terminates TLS with the ACM certificate and passes plain HTTP to nginx
# in the proxy's task. Its idle timeout is nginx's proxy_read_timeout in docs/fronting-tls.md.

resource "aws_lb" "main" {
  name                       = var.name
  load_balancer_type         = "application"
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  idle_timeout               = 300
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
}

resource "aws_lb_target_group" "proxy" {
  name                 = var.name
  vpc_id               = aws_vpc.main.id
  target_type          = "ip"
  protocol             = "HTTP"
  port                 = 80
  deregistration_delay = 30

  health_check {
    path    = "/-/byrle/health"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

locals {
  proxy_host = regex("^https://([^/:]+)", var.proxy_url)[0]
}

resource "aws_route53_record" "proxy" {
  count = var.route53_zone_id == "" ? 0 : 1

  zone_id = var.route53_zone_id
  name    = local.proxy_host
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
