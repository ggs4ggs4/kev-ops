data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default_public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  selected_subnet_id = sort(data.aws_subnets.default_public.ids)[0]
}

resource "aws_security_group" "mcp_server" {
  name        = "${var.project_name}-sg"
  description = "Security group for KEV-OPS MCP server"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "MCP public port"
    from_port   = var.host_port
    to_port     = var.host_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-sg"
  }
}

resource "aws_instance" "mcp_server" {
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type
  subnet_id     = local.selected_subnet_id
  key_name      = var.key_name

  vpc_security_group_ids      = [aws_security_group.mcp_server.id]
  associate_public_ip_address = true
  user_data_replace_on_change = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_size_gb
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    repo_url                 = var.repo_url
    repo_ref                 = var.repo_ref
    host_port                = var.host_port
    app_domain               = var.app_domain
    auth_required            = var.auth_required
    auth0_issuer             = var.auth0_issuer
    auth0_audience           = var.auth0_audience
    auth0_jwks_uri           = var.auth0_jwks_uri
    auth0_tier_claim         = var.auth0_tier_claim
    auth0_roles_claim        = var.auth0_roles_claim
    auth0_default_tier       = var.auth0_default_tier
    auth_required_scopes_csv = var.auth_required_scopes_csv
    nvd_api_key              = var.nvd_api_key
    log_level                = var.log_level
  })

  tags = {
    Name = "${var.project_name}-ec2"
  }
}

resource "aws_eip" "mcp_server" {
  domain   = "vpc"
  instance = aws_instance.mcp_server.id

  tags = {
    Name = "${var.project_name}-eip"
  }
}
