########################################
##          GLOBAL VARIABLES          ##
########################################
variable "sns_notification_email" {
  description = "The email address for the SNS topic used for Security alerts."
  type        = string
  default     = "security-alerts@company.com"
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.sns_notification_email))
    error_message = "The 'sns_notification_email' must be a valid email address format (e.g., user@domain.com)."
  }
}

variable "dry_run" {
  description = "If true, enables Dry Run Mode"
  type        = bool
  default     = false
}

########################################
##       EC2 SPECIFIC VARIABLES       ##
########################################
variable "ec2_19_enabled" {
  description = "If true, enables the remediation for Security Hub finding EC2.19 (Security Groups with unrestricted ingress)."
  type        = bool
  default     = false
}

variable "ec2_19_exception_bool_tag" {
  description = "AWS TAG to look for on alerting Security Group; if Tag exists and value set to true, then skip remediation"
  type        = string
  default     = "internetFacing"

  validation {
    condition = alltrue([
      can(regex("^[\\p{L}\\p{N}\\s.:/=+@_-]{1,128}$", var.ec2_19_exception_bool_tag)),
      !startswith(lower(var.ec2_19_exception_bool_tag), "aws:")
    ])
    
    error_message = "The tag key must be 1-128 characters, cannot start with 'aws:', and can only contain letters, numbers, spaces, and the characters: . : + = @ _ / - (hyphen)."
  }
}

variable "ec2_19_remediation_action" {
  description = "The action to take: 'UPDATE' (replace rule with VPC CIDRs) or 'REVOKE' (remove rule entirely)."
  type        = string
  default     = "UPDATE"
  validation {
    condition     = contains(["UPDATE", "REVOKE"], upper(var.ec2_19_remediation_action))
    error_message = "The remediation_action must be 'UPDATE' or 'REVOKE'."
  }
}

variable "ec2_19_replacement_cidrs" {
  description = "List of CIDR blocks to replace 0.0.0.0/0 and ::/0 with if action is 'UPDATE'."
  type        = list(string)
  default = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7"
  ]
}