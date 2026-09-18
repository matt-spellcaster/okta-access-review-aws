# One role per function, each with only what that function does. In particular:
#   - only collect and verify can read the Okta key
#   - only interact can read the Slack signing secret
#   - only functions that open or comment on tickets can read the Jira token
#   - evidence writes are limited to each function's own record kinds, and the
#     bucket policy makes every one of them create-only
#   - no role can delete evidence or bypass retention

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each           = local.functions
  name               = "${local.prefix}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

locals {
  ev        = aws_s3_bucket.evidence.arn
  work      = aws_s3_bucket.work.arn
  param_arn = { for k, v in local.params : k => "arn:aws:ssm:${var.region}:${local.account_id}:parameter${v}" }

  # What each function may do beyond writing its own logs.
  grants = {
    collect = {
      params         = ["okta_private_key"]
      evidence_read  = ["runs/*"]
      evidence_write = ["runs/*"]
      work_read      = ["inputs/*"]
      work_write     = []
      invoke         = []
      sfn_callback   = false
    }
    open = {
      params         = ["slack_bot_token", "jira_api_token"]
      evidence_read  = ["runs/*"]
      evidence_write = ["runs/*/tickets/*"]
      work_read      = ["state/*"]
      work_write     = ["state/*"]
      invoke         = []
      sfn_callback   = false
    }
    interact = {
      params         = ["slack_signing_secret", "slack_bot_token"]
      evidence_read  = ["runs/*/review_items.json"]
      evidence_write = []
      work_read      = []
      work_write     = []
      invoke         = ["worker"]
      sfn_callback   = false
    }
    worker = {
      params         = ["slack_bot_token"]
      evidence_read  = ["runs/*"]
      evidence_write = ["runs/*/decisions/*", "runs/*/signoff/*"]
      work_read      = ["state/*"]
      work_write     = ["state/*"]
      invoke         = []
      sfn_callback   = true
    }
    remediate = {
      params         = ["slack_bot_token", "jira_api_token"]
      evidence_read  = ["runs/*"]
      evidence_write = ["runs/*/tickets/*"]
      work_read      = ["state/*"]
      work_write     = ["state/*"]
      invoke         = []
      sfn_callback   = false
    }
    failed = {
      params         = ["slack_bot_token"]
      evidence_read  = []
      evidence_write = []
      work_read      = []
      work_write     = []
      invoke         = []
      sfn_callback   = false
    }
    watch = {
      params         = ["slack_bot_token", "jira_api_token"]
      evidence_read  = ["runs/*"]
      evidence_write = []
      work_read      = ["state/*"]
      work_write     = ["state/*", "markers/*"]
      invoke         = []
      sfn_callback   = true
    }
    verify = {
      params         = ["okta_private_key", "slack_bot_token", "jira_api_token"]
      evidence_read  = ["runs/*"]
      evidence_write = ["runs/*/verifications/*"]
      work_read      = ["inputs/*", "state/*"]
      work_write     = ["state/*", "markers/*"]
      invoke         = []
      sfn_callback   = false
    }
  }
}

data "aws_iam_policy_document" "fn" {
  for_each = local.functions

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
  }

  statement {
    sid       = "Secrets"
    actions   = ["ssm:GetParameter"]
    resources = [for p in local.grants[each.key].params : local.param_arn[p]]
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].evidence_read) > 0 ? [1] : []
    content {
      sid       = "ReadEvidence"
      actions   = ["s3:GetObject"]
      resources = [for p in local.grants[each.key].evidence_read : "${local.ev}/${p}"]
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].evidence_read) > 0 ? [1] : []
    content {
      sid       = "ListEvidence"
      actions   = ["s3:ListBucket"]
      resources = [local.ev]
      condition {
        test     = "StringLike"
        variable = "s3:prefix"
        values   = ["runs/*"]
      }
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].evidence_write) > 0 ? [1] : []
    content {
      sid       = "WriteEvidenceCreateOnly"
      actions   = ["s3:PutObject"]
      resources = [for p in local.grants[each.key].evidence_write : "${local.ev}/${p}"]
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].work_read) > 0 ? [1] : []
    content {
      sid       = "ReadWork"
      actions   = ["s3:GetObject"]
      resources = [for p in local.grants[each.key].work_read : "${local.work}/${p}"]
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].work_read) > 0 ? [1] : []
    content {
      sid       = "ListWork"
      actions   = ["s3:ListBucket"]
      resources = [local.work]
      condition {
        test     = "StringLike"
        variable = "s3:prefix"
        values   = [for p in local.grants[each.key].work_read : p]
      }
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].work_write) > 0 ? [1] : []
    content {
      sid       = "WriteWork"
      actions   = ["s3:PutObject"]
      resources = [for p in local.grants[each.key].work_write : "${local.work}/${p}"]
    }
  }

  dynamic "statement" {
    for_each = length(local.grants[each.key].invoke) > 0 ? [1] : []
    content {
      sid       = "InvokeWorker"
      actions   = ["lambda:InvokeFunction"]
      resources = [for f in local.grants[each.key].invoke : "arn:aws:lambda:${var.region}:${local.account_id}:function:${local.prefix}-${f}"]
    }
  }

  dynamic "statement" {
    for_each = local.grants[each.key].sfn_callback ? [1] : []
    content {
      sid     = "SignOffCallback"
      actions = ["states:SendTaskSuccess"]
      # SendTaskSuccess has no resource-level permissions; the task token is
      # what ties a call to one waiting execution.
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.functions
  name     = "function"
  role     = aws_iam_role.fn[each.key].id
  policy   = data.aws_iam_policy_document.fn[each.key].json
}
