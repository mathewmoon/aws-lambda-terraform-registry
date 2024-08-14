terraform {
  required_providers {
    jwks = {
      source  = "iwarapter/jwks"
      version = "0.1.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">=3.0.0"
    }
  }
}
provider "jwks" {}

provider "aws" {
  region = "us-east-1"
}
