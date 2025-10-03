#########################################
##               GLOBAL                ##
#########################################
data "aws_partition" "current" {}

resource "aws_sns_topic" "security_alert" {
  name = "Lambda-SecurityHub-Remediator-Alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.security_alert.arn
  protocol  = "email"
  endpoint  = var.sns_notification_email
}

resource "aws_iam_role" "remediation_lambda_role" {
  name               = "Lambda-SecurityHub-Remediator-Role"
  count              = local.lambda_needed ? 1 : 0
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}


#########################################
##    SHARED RESOURCES - UPDATE THIS   ##
#########################################
locals {
  # Helper to determine if the Lambda should be created at all
  # lambda_needed = var.ec2_19_enabled || var.future_boolean || var.future_boolean2
  lambda_needed = var.ec2_19_enabled

  # Conditional remediation action: Set to 'SKIP' in LAMBDA if the feature is disabled
  ec2_19_effective_action = var.ec2_19_enabled ? upper(var.ec2_19_remediation_action) : "SKIP"
}

resource "aws_iam_policy" "remediation_lambda_policy" {
  name  = "Lambda-SecurityHub-Remediator-Policy"
  count = local.lambda_needed ? 1 : 0

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowCloudWatchLogging",
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow",
        Resource = "arn:${data.aws_partition.current.partition}:logs:*:*:*"
      },
      {
        Sid      = "AllowSNSPublishing",
        Action   = ["sns:Publish"],
        Effect   = "Allow",
        Resource = aws_sns_topic.security_alert.arn
      },
      # Used By: EC2.19
      {
        Sid      = "AllowEC2SecurityGroupModification",
        Action   = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeTags"
        ],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediation_lambda_attach" {
  count      = local.lambda_needed ? 1 : 0
  role       = aws_iam_role.remediation_lambda_role[0].name
  policy_arn = aws_iam_policy.remediation_lambda_policy[0].arn
}

# 5. Lambda Function (Centralized logic for all findings)
data "archive_file" "lambda_zip" {
  count       = local.lambda_needed ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/lambda/"
  output_path = "${path.module}/lambda_handler.zip"
}

resource "aws_lambda_function" "remediator" {
  count            = local.lambda_needed ? 1 : 0
  filename         = data.archive_file.lambda_zip[0].output_path
  function_name    = "SecurityHub-Remediator"
  role             = aws_iam_role.remediation_lambda_role[0].arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip[0].output_base64sha256
  timeout          = 180

  # Environment variables for ALL remediations
  environment {
    variables = {
      # GLOBAL
      SNS_TOPIC_ARN             = aws_sns_topic.security_alert.arn
      DRY_RUN                   = var.dry_run ? "true" : "false"
      # EC2.19
      EC2_19_EXCEPTION_TAG      = var.ec2_19_exception_bool_tag
      EC2_19_REMEDIATION_ACTION = local.ec2_19_effective_action
      EC2_19_REPLACEMENT_CIDRS  = join(",", var.ec2_19_replacement_cidrs)
    }
  }
}

#########################################
##          EC2 Remediations           ##
#########################################
resource "aws_cloudwatch_event_rule" "ec2_19_trigger" {
  count       = var.ec2_19_enabled ? 1 : 0
  name        = "SecurityHub-EC2-19-Trigger"
  description = "Triggers Lambda when Security Hub detects EC2.19 finding (Unrestricted Ingress)."
  event_pattern = jsonencode({
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Compliance": {
          "Status": ["FAILED"]
        },
        "ProductFields": {
          "controlId": ["EC2.19"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "ec2_19_lambda_target" {
  count = var.ec2_19_enabled ? 1 : 0
  rule  = aws_cloudwatch_event_rule.ec2_19_trigger[0].name
  arn   = aws_lambda_function.remediator[0].arn
}

resource "aws_lambda_permission" "ec2_19_allow_cloudwatch" {
  count         = var.ec2_19_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatchEC219"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_19_trigger[0].arn
}

#########################################
##          TBD Remediations           ##
#########################################
