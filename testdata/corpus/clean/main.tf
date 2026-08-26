terraform {
  required_version = ">= 1.9.0"
}

variable "node_port_http" {
  description = "NodePort for plain HTTP. Pinned; the firewall rules name it."
  type        = number
  default     = 30080
}

variable "node_port_https" {
  type    = number
  default = 30443
}

resource "aws_security_group_rule" "gateway_https" {
  type              = "ingress"
  from_port         = var.node_port_https
  to_port           = var.node_port_https
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8", "172.16.0.0/12"]
  security_group_id = "sg-0a1b2c3d4e5f60718"
}

output "cluster_endpoint" {
  value = "https://10.96.0.1:6443"
}

output "documentation_example_addresses" {
  description = "RFC 5737 ranges, used in the runbook so nobody pastes a real one."
  value       = ["192.0.2.1", "198.51.100.14", "203.0.113.7"]
}
