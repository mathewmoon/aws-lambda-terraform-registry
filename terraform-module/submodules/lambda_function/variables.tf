variable "name" {
  description = "The name of the Lambda function"
  type        = string
}

variable "handler" {
  description = "The entry point of the Lambda function"
  type        = string
  default     = "lambda_function.lambda_handler"
}

variable "runtime" {
  description = "The runtime of the Lambda function"
  type        = string
  default     = "python3.12"
}

variable "timeout" {
  description = "The timeout of the Lambda function"
  type        = number
  default     = 8
}

variable "memory_size" {
  description = "The memory size of the Lambda function"
  type        = number
  default     = 1024
}

variable "environment" {
  description = "The environment variables of the Lambda function"
  type        = map(string)
  default     = {}
}

variable "role_arn" {
  description = "The ARN of the IAM role that the Lambda function assumes"
  type        = string
}

variable "registry_version" {
  description = "The version of the registry python package to use."
  type        = string
}

variable "registry_package" {
  description = "The name of the pip package to install in the Lambda function."
  type        = string
  default     = "lambda-terraform-module-registry"
}

variable "auth_type" {
  description = "The type of authorization to use for the Lambda function"
  type        = string

  validation {
    condition     = var.auth_type == "NONE" || var.auth_type == "AWS_IAM"
    error_message = "auth_type must be either 'NONE' or 'AWS_IAM'"
  }
}

variable "powertools_layer_version" {
  description = "The version of the AWS Lambda Powertools Python V2 layer to use."
  type        = string
}
