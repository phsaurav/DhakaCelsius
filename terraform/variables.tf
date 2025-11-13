# * Tags
variable "project" {
  description = "Project Name"
  type        = string
  default     = "dhaka-celsius"
}
variable "createdby" {
  description = "Current Developer"
  type        = string
}

# * General 
variable "aws_region" {
  description = "Region code"
  type        = string
}
variable "profile" {
  description = "Environment AWS Profile"
  type        = string

}
variable "environment" {
  description = "Environment Name"
  type        = string

  validation {
    condition     = var.environment == terraform.workspace
    error_message = "Workspace & Variable File Inconsistency!! Please Double Check!!"
  }
}

# * VPC
variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR range"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_public_subnets" {
  description = "List of public subnet CIDR ranges"
  type        = list(string)
  default     = ["10.0.0.0/20", "10.0.16.0/20", "10.0.32.0/20"]
}

variable "vpc_private_subnets" {
  description = "List of private subnet CIDR ranges"
  type        = list(string)
  default     = ["10.0.128.0/20", "10.0.144.0/20", "10.0.160.0/20"]
}

variable "vpc_single_nat_gateway" {
  description = "Should vpc keep one shared nat gateway or nat gateway for each AZ"
  type        = bool
}

variable "enable_nat_gateway" {
  description = "NAT Gateway or NAT Instance"
  type        = bool
}

#EKS
variable "eks_min_capacity" {
  description = "EKS minimum size"
  type        = number
  default     = 1
}

variable "eks_max_capacity" {
  description = "Auto scaling maximum size"
  type        = number
  default     = 1
}

variable "eks_desired_capacity" {
  description = "EKS desired capacity"
  type        = number
  default     = 1
}

variable "instance_types" {
  description = "List of instance type"
  type = list(string)
  default = ["t4g.small"]
}

variable "eks_disk_size" {
  description = "EKS disk size"
  type        = number
  default     = 20
}


