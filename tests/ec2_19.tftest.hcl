run "ec2_19_creation_test" {
  variables {
    ec2_19_enabled = true
  }

  assert {
    condition     = length(aws_lambda_function.remediator) > 0
    error_message = "Lambda function was not created when ec2_19_enabled was set to true."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.ec2_19_trigger) > 0
    error_message = "EC2.19 EventBridge rule was not created when ec2_19_enabled was set to true."
  }
}

run "ec2_19_disabled_test" {
  variables {
    ec2_19_enabled = false
  }

  assert {
    condition     = length(aws_lambda_function.remediator) == 0
    error_message = "Lambda function was incorrectly created when no event bridge rules were enabled"
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.ec2_19_trigger) == 0
    error_message = "EC2.19 EventBridge rule was incorrectly created when ec2_19_enabled was set to false."
  }
}