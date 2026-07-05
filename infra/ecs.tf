resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.prefix}-cloudjuice"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "main" {
  name = "${local.prefix}-cluster"
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_ecs_task_definition" "cloudjuice" {
  family                   = "${local.prefix}-cloudjuice"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = local.lab_role_arn
  task_role_arn            = local.lab_role_arn

  container_definitions = jsonencode([
    {
      name      = "cloudjuice"
      image     = "${aws_ecr_repository.cloudjuice.repository_url}:${var.image_tag}"
      essential = true
      portMappings = [
        { containerPort = var.container_port, protocol = "tcp" }
      ]
      environment = [
        { name = "PORT", value = tostring(var.container_port) },
        { name = "BLOCKLIST_URL", value = "${aws_apigatewayv2_api.http.api_endpoint}/blocklist" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "cloudjuice"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "cloudjuice" {
  name            = "${local.prefix}-cloudjuice"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.cloudjuice.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.cloudjuice.arn
    container_name   = "cloudjuice"
    container_port   = var.container_port
  }

  health_check_grace_period_seconds = 60

  depends_on = [aws_lb_listener.http]
}
