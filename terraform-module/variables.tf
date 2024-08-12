variable "dynamodb_table_name" {
  description = "The name of the DynamoDB table"
  type        = string
  default     = "terraform-registry"
}

variable "dynamodb_cmk" {
  description = "The ARN of the KMS key used to encrypt the DynamoDB table. If omitted, the table will use AWS managed keys."
  type        = string
  default     = null
}

variable "dynamodb_pitr" {
  description = "Whether to enable point-in-time recovery for the DynamoDB table"
  type        = bool
  default     = true
}

variable "dynamodb_billing_mode" {
  description = "The billing mode of the DynamoDB table"
  type        = string
  default     = "PAY_PER_REQUEST"
  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.dynamodb_billing_mode)
    error_message = "Billing mode must be either PAY_PER_REQUEST or PROVISIONED"
  }
}

variable "dynamodb_ttl" {
  description = "The TTL attribute of the DynamoDB table"
  type        = string
  default     = "TTL"
}

variable "dynamodb_read_capacity" {
  description = "The read capacity unitis of the DynamoDB table"
  type        = number
  default     = 5
}

variable "dynamodb_write_capacity" {
  description = "The write capacity unitis of the DynamoDB table"
  type        = number
  default     = 5
}

variable "registry_function_name" {
  description = "The name of the registry Lambda function"
  type        = string
  default     = "terraform-registry"
}

variable "iam_auth_function_name" {
  description = "The name of the IAM auth Lambda function"
  type        = string
  default     = "terraform-iam-token-endpoint"
}

variable "kms_alias" {
  description = "The alias of the KMS key to use for the application"
  type        = string
  default     = "alias/terraform-registry"
}

variable "bucket_name" {
  description = "The name of the S3 bucket"
  type        = string
}

variable "bucket_versioning" {
  description = "Whether to enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "create_bucket" {
  description = "Whether to create an S3 bucket for the registry"
  type        = bool
  default     = true
}

variable "bucket_arn" {
  description = "The ARN of an existing S3 bucket to use for the registry"
  type        = string
  default     = null
}

variable "registry_api_name" {
  description = "The name of the API Gateway"
  type        = string
  default     = "terraform-registry"
}

variable "allowed_registry_identities" {
  description = "The identities allowed to access the registry via resource policies"
  type        = list(string)
  default     = []
}

variable "allow_organization_access" {
  description = "Whether to allow access to the registry from the entire organization"
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "The domain name for the API Gateway"
  type        = string
  default     = null
}

variable "certificate_arn" {
  description = "The ARN of the ACM certificate to use for the API Gateway"
  type        = string
  default     = null
}
