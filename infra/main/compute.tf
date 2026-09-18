# One image, one function per handler (src/access_review/aws/handlers.py).

resource "aws_ecr_repository" "app" {
  name                 = "${local.prefix}-app"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}

locals {
  common_env = {
    EVIDENCE_BUCKET       = aws_s3_bucket.evidence.bucket
    WORK_BUCKET           = aws_s3_bucket.work.bucket
    SLACK_CHANNEL_ID      = var.slack_channel_id
    SLACK_ADMIN_USER      = var.slack_admin_user
    SLACK_CISO_USER       = var.slack_ciso_user
    SLACK_BOT_TOKEN_PARAM = local.params.slack_bot_token
    REVIEW_DAYS           = tostring(var.review_days)
    LEAVER_TICKET_HOURS   = tostring(var.leaver_ticket_hours)
    REVOKE_TICKET_DAYS    = tostring(var.revoke_ticket_days)
  }
  okta_env = {
    OKTA_ORG_URL           = var.okta_org_url
    OKTA_CLIENT_ID         = var.okta_client_id
    OKTA_KEY_ID            = var.okta_key_id
    OKTA_PRIVATE_KEY_PARAM = local.params.okta_private_key
  }
  jira_env = {
    JIRA_BASE_URL        = var.jira_base_url
    JIRA_EMAIL           = var.jira_email
    JIRA_PROJECT         = var.jira_project
    JIRA_PARENT_TYPE     = var.jira_parent_type
    JIRA_CHILD_TYPE      = var.jira_child_type
    JIRA_API_TOKEN_PARAM = local.params.jira_api_token
  }

  # handler, timeout (s), memory (MB), reserved concurrency, extra environment
  functions = {
    collect   = { handler = "collect", timeout = 900, memory = 1024, concurrency = 1, env = local.okta_env }
    open      = { handler = "open_review", timeout = 300, memory = 512, concurrency = 1, env = local.jira_env }
    interact  = { handler = "interact", timeout = 10, memory = 512, concurrency = 5, env = { SLACK_SIGNING_SECRET_PARAM = local.params.slack_signing_secret, WORKER_FUNCTION = "${local.prefix}-worker" } }
    worker    = { handler = "worker", timeout = 120, memory = 512, concurrency = 5, env = {} }
    remediate = { handler = "remediate", timeout = 300, memory = 512, concurrency = 1, env = local.jira_env }
    failed    = { handler = "failed", timeout = 30, memory = 256, concurrency = 1, env = {} }
    watch     = { handler = "watch_hourly", timeout = 300, memory = 512, concurrency = 1, env = local.jira_env }
    verify    = { handler = "verify_daily", timeout = 900, memory = 1024, concurrency = 1, env = merge(local.okta_env, local.jira_env) }
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.functions
  name              = "/aws/lambda/${local.prefix}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "fn" {
  for_each      = local.functions
  function_name = "${local.prefix}-${each.key}"
  role          = aws_iam_role.fn[each.key].arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.app.repository_url}@${var.image_digest}"
  architectures = ["arm64"]
  timeout       = each.value.timeout
  memory_size   = each.value.memory

  reserved_concurrent_executions = each.value.concurrency

  image_config {
    command = ["access_review.aws.handlers.${each.value.handler}"]
  }

  environment {
    variables = merge(local.common_env, each.value.env)
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.fn[each.key].name
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
}
