# Terraform Deployment (Cheap EC2 Setup)

This stack provisions a low-cost deployment for the KEV-OPS MCP server:

- 1x EC2 instance (`t3a.micro` by default)
- 1x Elastic IP
- 1x Security Group (public MCP port + SSH)
- bootstrap via `user_data`:
  - installs Docker + Docker Compose
  - clones your repository
  - writes `.env`
  - runs `docker compose up -d --build`

No ALB, no NAT, no RDS, no paid managed services.  
This is intentionally optimized for hackathon budget.

## Prerequisites

- Terraform 1.5+
- AWS credentials configured
- repo pushed to a reachable Git URL
- Auth0 API configured (issuer/audience/JWKS)

## Usage

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars

terraform init
terraform plan
terraform apply
```

After apply:

```bash
terraform output mcp_endpoint_url
terraform output health_url
terraform output public_ip
```

## Notes

- If `app_domain` is empty, bootstrap uses `<elastic-ip>.nip.io`.
- `host_port=80` is cheapest/simplest for demos.
- Commit `.terraform.lock.hcl` to the repo. Do not commit `.terraform/`, `terraform.tfvars`, or `*.tfstate`.
- To destroy everything:

```bash
terraform destroy
```
