locals {
  endpoint_host = var.app_domain != "" ? var.app_domain : "${replace(aws_eip.mcp_server.public_ip, ".", "-")}.nip.io"
  endpoint_url  = var.host_port == 80 ? "http://${local.endpoint_host}/mcp" : "http://${local.endpoint_host}:${var.host_port}/mcp"
}

output "instance_id" {
  value       = aws_instance.mcp_server.id
  description = "EC2 instance ID."
}

output "public_ip" {
  value       = aws_eip.mcp_server.public_ip
  description = "Elastic IP attached to the server."
}

output "mcp_endpoint_url" {
  value       = local.endpoint_url
  description = "Public MCP endpoint URL."
}

output "health_url" {
  value       = var.host_port == 80 ? "http://${local.endpoint_host}/health" : "http://${local.endpoint_host}:${var.host_port}/health"
  description = "Health endpoint URL."
}

output "ssh_command" {
  value       = var.key_name != null ? "ssh ec2-user@${aws_eip.mcp_server.public_ip}" : "No key_name provided; SSH command unavailable."
  description = "Convenience SSH command."
}
