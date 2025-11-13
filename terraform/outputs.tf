# * General Outputs
output "environment" {
  description = "The environment name"
  value       = var.environment
}

output "project" {
  description = "The project name"
  value       = var.project
}

# * VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block for the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "vpc_private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "vpc_public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

# ECR
output "ecr_public_repository_uri" {
  value = module.ecr.ecr_public_repository_uri
  description = "URI of the public ECR repository"
}