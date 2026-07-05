resource "aws_s3_bucket" "spa" {
  bucket        = local.spa_bucket
  force_destroy = true
}

# Public static site for the demo console.
resource "aws_s3_bucket_public_access_block" "spa" {
  bucket                  = aws_s3_bucket.spa.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_website_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id
  index_document { suffix = "index.html" }
  error_document { key = "index.html" }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket = aws_s3_bucket.spa.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.spa.arn}/*"
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.spa]
}

# Static assets - uploaded and versioned by Terraform (etag tracks changes).
resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.spa.id
  key          = "index.html"
  source       = "${path.module}/../spa/index.html"
  etag         = filemd5("${path.module}/../spa/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "styles" {
  bucket       = aws_s3_bucket.spa.id
  key          = "styles.css"
  source       = "${path.module}/../spa/styles.css"
  etag         = filemd5("${path.module}/../spa/styles.css")
  content_type = "text/css"
}

resource "aws_s3_object" "appjs" {
  bucket       = aws_s3_bucket.spa.id
  key          = "app.js"
  source       = "${path.module}/../spa/app.js"
  etag         = filemd5("${path.module}/../spa/app.js")
  content_type = "application/javascript"
}

resource "aws_s3_object" "catalogjs" {
  bucket       = aws_s3_bucket.spa.id
  key          = "catalog.js"
  source       = "${path.module}/../spa/catalog.js"
  etag         = filemd5("${path.module}/../spa/catalog.js")
  content_type = "application/javascript"
}

resource "aws_s3_object" "apijs" {
  bucket       = aws_s3_bucket.spa.id
  key          = "api.js"
  source       = "${path.module}/../spa/api.js"
  etag         = filemd5("${path.module}/../spa/api.js")
  content_type = "application/javascript"
}

# Runtime config with the deployed API endpoint injected at apply time.
resource "aws_s3_object" "config" {
  bucket       = aws_s3_bucket.spa.id
  key          = "config.js"
  content_type = "application/javascript"
  content = templatefile("${path.module}/../spa/config.js.tftpl", {
    api_base = aws_apigatewayv2_api.http.api_endpoint
  })
}
