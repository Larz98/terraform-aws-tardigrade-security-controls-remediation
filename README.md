# terraform-aws-tardigrade-security-controls-remediation

This module provides a centralized, event-driven solution to automatically remediate non-compliant resources identified by **AWS Security Config/Hub**.

The core architecture uses a single **AWS Lambda function**, triggered by **Amazon EventBridge** rules based on Security findings. 
Remediation logic is executed based on configurable Terraform variables.

---

## Usage

To use this module, include it in your root or environment Terraform configuration and set the necessary variables to enable the desired security controls.

### Example: Enabling EC2.19 Remediation - MODIFY rules

```terraform
module "security_remediator" {
  source = "./aws-remediation-module"

  # ------------------------------------------------------------------
  # CORE CONFIGURATION
  # ------------------------------------------------------------------
  sns_notification_email = "security-alerts@customer.domain"

  # ------------------------------------------------------------------
  # EC2.19 - Security Groups should not allow unrestricted ingress
  # ------------------------------------------------------------------
  ec2_19_enabled            = true              # deploy EC2.19 EventBridge rule
  ec2_19_exception_bool_tag = "internetFacing"  # If TAG exists and has a truthy val: skip action
  ec2_19_remediation_action = "UPDATE"          # Options: "UPDATE" or "REVOKE"
  ec2_19_replacement_cidrs  = [
    "10.0.0.0/16",      # Specific internal network
    "192.168.0.0/24"    # Another specific internal network
  ]                                             # When action is 'UPDATE', replace CIDRs
}
```

## Full Variable Table

| Variable Name             | Type         | Default Value                                                 | Description |
| :--- | :--- | :--- | :--- |
| sns_notification_email    | string       | "security@example.com"                                        | The email address subscribed to the central SNS alert topic. |
| ec2_19_enabled            | bool         | true                                                          | Set to true to enable automated remediation for EC2.19. Accepts case-insensitive boolean alternatives (e.g., 'Yes', '1', 'TRUE'). |
| ec2_19_exception_bool_tag | string       | "Exception:Public-Access"                                     | AWS TAG to look for on Security Group;  if exists and set to true, then skip remediation |
| ec2_19_remediation_action | string       | "UPDATE"                                                      | The action to take for EC2.19: UPDATE (replace rule with approved CIDRs) or REVOKE (remove the rule entirely and send an SNS alert). |
| ec2_19_replacement_cidrs  | list(string) | ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"] | List of CIDR blocks to use when ec2_19_remediation_action is UPDATE. |

## Security Controls Logic

### EC2.19: Security Group Unrestricted Ingress
| Feature       | Description |
| :--- | :--- |
| Trigger       | Security Hub finding `security-control/EC2.19` status `FAILED`. |
| Exception Tag | If the affected Security Group has the tag defined in `ec2_19_exception_bool_tag` with a value of `TRUE`, remediation is skipped. |
| UPDATE Action | `Revoke` the offending `0.0.0.0/0` or `::/0` ingress rule and replace with new rules from `ec2_19_replacement_cidrs`. |
| REVOKE Action | `Revoke` the offending `0.0.0.0/0` or `::/0` ingress rule and publish SNS alert to `sns_notification_email`. |

