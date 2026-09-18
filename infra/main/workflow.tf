resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${local.prefix}-review"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "sfn_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${local.prefix}-review-sfn"
  assume_role_policy = data.aws_iam_policy_document.sfn_trust.json
}

data "aws_iam_policy_document" "sfn" {
  statement {
    sid       = "InvokeSteps"
    actions   = ["lambda:InvokeFunction"]
    resources = [for f in ["collect", "open", "remediate", "failed"] : aws_lambda_function.fn[f].arn]
  }
  statement {
    sid = "Logging"
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "review"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "review" {
  name     = "${local.prefix}-review"
  role_arn = aws_iam_role.sfn.arn
  type     = "STANDARD"

  definition = templatefile("${path.module}/review.asl.json", {
    collect_arn             = aws_lambda_function.fn["collect"].arn
    open_arn                = aws_lambda_function.fn["open"].arn
    remediate_arn           = aws_lambda_function.fn["remediate"].arn
    failed_arn              = aws_lambda_function.fn["failed"].arn
    signoff_timeout_seconds = var.signoff_timeout_days * 86400
  })

  # Errors only, and never state data: execution history already holds the
  # (counts-only) state, and logs are kept separately.
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  depends_on = [aws_iam_role_policy.sfn]
}
