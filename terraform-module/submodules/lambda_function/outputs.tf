output "arn" {
  description = "The ARN of the Lambda function"
  value       = aws_lambda_function.this.arn
}

output "function_name" {
  description = "The name of the Lambda function"
  value       = aws_lambda_function.this.function_name
}

output "url" {
  description = "The URL of the Lambda function"
  value       = aws_lambda_function_url.this.function_url
}
