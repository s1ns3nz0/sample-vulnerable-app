# Payment API Infrastructure — INTENTIONALLY MISCONFIGURED
# These misconfigurations are detected by Checkov

provider "aws" {
  region = "ap-northeast-1"
}

# VULNERABILITY: S3 bucket without encryption (CKV_AWS_19 → PCI-DSS-3.4)
# VULNERABILITY: S3 bucket without versioning (CKV_AWS_21 → FISC-DATA-03)
# VULNERABILITY: S3 bucket without access logging (CKV_AWS_18 → PCI-DSS-3.4)
resource "aws_s3_bucket" "payment_data" {
  bucket = "payment-api-data-store"

  tags = {
    Name        = "payment-data"
    Environment = "production"
    Compliance  = "PCI-DSS"
  }
}

# Missing: aws_s3_bucket_server_side_encryption_configuration
# Missing: aws_s3_bucket_versioning
# Missing: aws_s3_bucket_logging
# Missing: aws_s3_bucket_public_access_block

# VULNERABILITY: Overly permissive IAM policy (CKV_AWS_1 → FISC-ACCESS-07)
resource "aws_iam_policy" "payment_api_policy" {
  name        = "payment-api-full-access"
  description = "Payment API access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # VULNERABILITY: wildcard action
        Resource = "*"           # VULNERABILITY: wildcard resource
      }
    ]
  })
}

resource "aws_iam_role" "payment_api_role" {
  name = "payment-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "payment_api_attach" {
  role       = aws_iam_role.payment_api_role.name
  policy_arn = aws_iam_policy.payment_api_policy.arn
}

# VULNERABILITY: Security group allows 0.0.0.0/0 ingress (CKV_AWS_24 → PCI-DSS-1.3.4)
resource "aws_security_group" "payment_api_sg" {
  name        = "payment-api-sg"
  description = "Payment API security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABILITY: SSH open to world
    description = "SSH access"
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABILITY: App port open to world
    description = "Application access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "payment-api-sg"
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "payment_api" {
  family                   = "payment-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.payment_api_role.arn
  task_role_arn            = aws_iam_role.payment_api_role.arn

  container_definitions = jsonencode([
    {
      name      = "payment-api"
      image     = "payment-api:latest"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "AWS_ACCESS_KEY_ID"
          value = "AKIAIOSFODNN7EXAMPLE"  # VULNERABILITY: hardcoded in task def
        }
      ]
    }
  ])
}
