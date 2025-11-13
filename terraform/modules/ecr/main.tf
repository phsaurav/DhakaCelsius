provider "aws" {
  alias   = "us-east-1"
  region  = "us-east-1"
}

resource "aws_ecrpublic_repository" "public_ecr" {
  repository_name = var.repo_name
  provider    = aws.us-east-1

  catalog_data {
    description     = "Public repository for ${var.repo_name}"
    architectures   = ["x86-64"]
    operating_systems = ["Linux"]
  }
}