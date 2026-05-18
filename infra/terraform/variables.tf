variable "aws_region" {
  description = "AWS region for deployment."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for naming and tagging."
  type        = string
  default     = "kevops-mcp"
}

variable "creator" {
  description = "Tag value for resource ownership."
  type        = string
  default     = "ganesh"
}

variable "purpose" {
  description = "Tag value describing why these resources exist."
  type        = string
  default     = "kd-ai-league"
}

variable "instance_type" {
  description = "EC2 instance type. Keep this small for low cost."
  type        = string
  default     = "t3a.micro"
}

variable "ami_id" {
  description = "Optional AMI override. When unset, latest Amazon Linux 2023 is used for first deploy."
  type        = string
  default     = ""
}

variable "root_volume_size_gb" {
  description = "Root EBS volume size in GB."
  type        = number
  default     = 12
}

variable "key_name" {
  description = "Optional existing EC2 key pair for SSH."
  type        = string
  default     = null
}

variable "ssh_cidr_blocks" {
  description = "CIDR blocks allowed to SSH into instance."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "repo_url" {
  description = "Git repository URL containing this project."
  type        = string
}

variable "repo_ref" {
  description = "Git ref (branch/tag/commit) to deploy."
  type        = string
  default     = "main"
}

variable "host_port" {
  description = "Public host port exposed for MCP server."
  type        = number
  default     = 80
}

variable "app_domain" {
  description = "Optional DNS host name. If empty, bootstrap script uses <public-ip>.nip.io."
  type        = string
  default     = ""
}

variable "auth_required" {
  description = "Whether OAuth bearer auth is required."
  type        = bool
  default     = true
}

variable "auth0_issuer" {
  description = "Auth0 issuer URL (e.g., https://tenant.us.auth0.com/)."
  type        = string
}

variable "auth0_audience" {
  description = "Primary Auth0 API audience identifier. Use a stable URI that does not depend on instance IP/host."
  type        = string
}

variable "auth0_audience_aliases_csv" {
  description = "Optional comma-separated extra audiences accepted by the resource server during transitions."
  type        = string
  default     = ""
}

variable "auth0_resource" {
  description = "Optional OAuth protected resource identifier to advertise in PRM. Defaults to auth0_audience."
  type        = string
  default     = ""
}

variable "auth0_jwks_uri" {
  description = "Auth0 JWKS URI."
  type        = string
}

variable "auth0_tier_claim" {
  description = "JWT claim key for user tier."
  type        = string
  default     = "https://kevops.example.com/tier"
}

variable "auth0_roles_claim" {
  description = "JWT claim key for role list."
  type        = string
  default     = "https://kevops.example.com/roles"
}

variable "auth0_default_tier" {
  description = "Default fallback tier if claim parsing fails."
  type        = string
  default     = "free"

  validation {
    condition     = contains(["free", "premium", "analyst"], var.auth0_default_tier)
    error_message = "auth0_default_tier must be one of: free, premium, analyst."
  }
}

variable "auth_required_scopes_csv" {
  description = "Comma-separated required scopes enforced by bearer middleware."
  type        = string
  default     = "mcp:tools"
}

variable "nvd_api_key" {
  description = "Optional NVD API key."
  type        = string
  default     = ""
  sensitive   = true
}

variable "log_level" {
  description = "Application log level."
  type        = string
  default     = "info"
}
