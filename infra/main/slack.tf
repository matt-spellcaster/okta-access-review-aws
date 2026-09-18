# Slack's interactivity endpoint. There is no AWS auth on it: Slack can't sign
# AWS requests. The Slack signing secret is the authentication, checked on
# every request before anything else (slack_interact.verify_signature), and
# reserved concurrency on the function caps what a flood of junk could cost.

resource "aws_lambda_function_url" "interact" {
  function_name      = aws_lambda_function.fn["interact"].function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "interact_url" {
  statement_id           = "SlackInteractivity"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.fn["interact"].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# Function URLs also need InvokeFunction, limited to calls made through the URL.
resource "aws_lambda_permission" "interact_url_invoke" {
  statement_id             = "SlackInteractivityInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.fn["interact"].function_name
  principal                = "*"
  invoked_via_function_url = true
}
