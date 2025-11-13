output "ecr_public_repository_uri" {
  value = aws_ecrpublic_repository.public_ecr.repository_uri
  description = "URI of the public ECR repository"
}