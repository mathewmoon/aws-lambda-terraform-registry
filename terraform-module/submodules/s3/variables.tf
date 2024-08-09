variable "bucket_name" {
  description = "The name of the S3 bucket"
  type        = string
}

variable "bucket_versioning" {
  description = "Whether to enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "kms_key" {
  description = "The ARN of the KMS key to use for the S3 bucket"
  type        = string
}
