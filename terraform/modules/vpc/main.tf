################################################################################
# Supporting Resources
################################################################################

# Security group for EC2 Instance Connect Endpoint
resource "aws_security_group" "ec2-connect-endpoint-sg" {
  name        = "dhaka-celsius-ec2-connect-endpoint-sg"
  description = "Security group for EC2 Instance Connect Endpoint"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  tags = merge(
    { Name = "dhaka-celsius-ec2-connect-endpoint-sg" },
    var.vpc_tags
  )
}

################################################################################
# Virtual private cloud (VPC)
################################################################################

# Get the availability zones
data "aws_availability_zones" "available" {}

# Get the first 3 availability zones
locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)
}

# Create the VPC
module "vpc" {
  source                 = "terraform-aws-modules/vpc/aws"
  version                = "5.18.1"
  name                   = var.vpc_name
  cidr                   = var.vpc_cidr
  azs                    = local.azs
  private_subnets        = var.vpc_private_subnets
  public_subnets         = var.vpc_public_subnets
  enable_dns_hostnames   = true
  enable_dns_support     = true
  enable_nat_gateway     = var.enable_nat_gateway
  single_nat_gateway     = var.vpc_single_nat_gateway
  one_nat_gateway_per_az = var.vpc_one_natgateway_per_az
  tags                   = var.vpc_tags
}


################################################################################
# EC2 Instance Connect Endpoint
################################################################################
resource "aws_ec2_instance_connect_endpoint" "ec2-connect-endpoint" {
  subnet_id          = module.vpc.private_subnets[0]
  security_group_ids = [aws_security_group.ec2-connect-endpoint-sg.id]

  tags = merge(
    { Name = "dhaka-celsius-ec2-connect-endpoint" },
    var.vpc_tags
  )
}
