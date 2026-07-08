resource "aws_s3_bucket" "vulnerable" {
  bucket = "vulnerable-app-data-${random_string.suffix.result}"

}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_versioning" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  versioning_configuration {
    status = "Disabled"
  }
}
