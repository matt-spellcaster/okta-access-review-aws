# Two buckets:
#   evidence  review runs, decisions, sign-offs, ticket and verification records.
#             Object Lock (governance) keeps every version for the retention
#             period; writes must be create-only; lifecycle deletes afterwards.
#   work      inputs (roster, config), review state and markers. Mutable, no lock.

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.prefix}-evidence-${local.account_id}"
  object_lock_enabled = true
  # Teardown empties it first (scripts/teardown.py); destroy never deletes evidence by itself.
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.evidence_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "expire-after-retention"
    status = "Enabled"
    filter {}
    # Adds a delete marker after retention; the locked version itself goes once
    # its retention has ended (lifecycle can't remove it earlier).
    expiration {
      days = var.evidence_retention_days + 30
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  rule {
    id     = "clean-delete-markers"
    status = "Enabled"
    filter {}
    expiration {
      expired_object_delete_marker = true
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket" "work" {
  bucket        = "${local.prefix}-work-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "work" {
  bucket = aws_s3_bucket.work.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "work" {
  bucket = aws_s3_bucket.work.id
  rule {
    id     = "markers"
    status = "Enabled"
    filter {
      prefix = "markers/"
    }
    expiration {
      days = 400
    }
  }
  rule {
    id     = "old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.work]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "buckets" {
  for_each = { evidence = aws_s3_bucket.evidence.id, work = aws_s3_bucket.work.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "buckets" {
  for_each                = { evidence = aws_s3_bucket.evidence.id, work = aws_s3_bucket.work.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "buckets" {
  for_each = { evidence = aws_s3_bucket.evidence.id, work = aws_s3_bucket.work.id }
  bucket   = each.value
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Evidence is create-only: a PUT without If-None-Match is refused, whoever sends it.
  statement {
    sid       = "CreateOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["true"]
    }
  }

  # Only the teardown role may shorten retention or delete versions.
  statement {
    sid    = "OnlyTeardownDeletes"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:PutObjectRetention",
      "s3:PutObjectLegalHold", "s3:PutBucketObjectLockConfiguration",
    ]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.teardown_role_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = data.aws_iam_policy_document.evidence_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.buckets]
}

data "aws_iam_policy_document" "work_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.work.arn, "${aws_s3_bucket.work.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "work" {
  bucket     = aws_s3_bucket.work.id
  policy     = data.aws_iam_policy_document.work_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.buckets]
}
