module "s3_bucket" {
  count = var.create_bucket ? 1 : 0

  source = "./submodules/s3"

  bucket_name       = var.bucket_name
  bucket_versioning = var.bucket_versioning
  kms_key           = aws_kms_key.this.arn
}
