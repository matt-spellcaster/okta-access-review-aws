data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.prefix}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.review.arn]
  }
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.fn["watch"].arn, aws_lambda_function.fn["verify"].arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "schedules"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "quarterly_review" {
  name                         = "${local.prefix}-quarterly-review"
  schedule_expression          = var.review_schedule
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_sfn_state_machine.review.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})
  }
}

resource "aws_scheduler_schedule" "hourly_watch" {
  name                = "${local.prefix}-hourly-watch"
  schedule_expression = "rate(1 hour)"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.fn["watch"].arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})
  }
}

resource "aws_scheduler_schedule" "daily_verify" {
  name                         = "${local.prefix}-daily-verify"
  schedule_expression          = "cron(0 7 * * ? *)"
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.fn["verify"].arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})
  }
}
