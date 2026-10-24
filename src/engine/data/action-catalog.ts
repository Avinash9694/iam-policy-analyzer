/** Verb prefixes that indicate an action changes state. */
export const MUTATING_VERBS: readonly string[] = [
  'Create',
  'Delete',
  'Put',
  'Update',
  'Modify',
  'Attach',
  'Detach',
  'Terminate',
  'Stop',
  'Start',
  'Reboot',
  'Run',
  'Invoke',
  'Set',
  'Remove',
  'Add',
  'Associate',
  'Disassociate',
  'Enable',
  'Disable',
  'Replace',
  'Reset',
  'Restore',
  'Revoke',
  'Authorize',
  'Register',
  'Deregister',
  'Tag',
  'Untag',
  'Write',
  'Send',
  'Publish',
  'Purge',
  'Import',
  'Cancel',
  'Reject',
  'Accept',
  'Approve',
  'Assign',
  'Unassign',
  'Change',
  'Copy',
  'Deploy',
  'Execute',
  'Grant',
  'Initiate',
  'Install',
  'Merge',
  'Move',
  'Promote',
  'Provision',
  'Rotate',
  'Schedule',
  'Submit',
  'Upload',
  'Upgrade',
  'Abort',
  'Allocate',
  'Release',
  'Reassign',
  'Resume',
];

/** Actions that warrant an MFA condition when granted to a human identity. */
export const MFA_SENSITIVE_ACTIONS: readonly string[] = [
  'iam:*',
  'organizations:*',
  'sts:AssumeRole',
  'kms:ScheduleKeyDeletion',
  'kms:DisableKey',
  'kms:PutKeyPolicy',
  's3:DeleteBucket',
  's3:DeleteBucketPolicy',
  's3:PutBucketPolicy',
  's3:PutBucketAcl',
  'ec2:TerminateInstances',
  'rds:DeleteDBInstance',
  'rds:DeleteDBCluster',
  'dynamodb:DeleteTable',
  'lambda:DeleteFunction',
  'cloudtrail:StopLogging',
  'cloudtrail:DeleteTrail',
  'cloudtrail:UpdateTrail',
  'config:StopConfigurationRecorder',
  'config:DeleteConfigurationRecorder',
  'guardduty:DeleteDetector',
  'account:CloseAccount',
];

/** Actions that read data (as opposed to metadata) and are dangerous on `*`. */
export const DATA_EXFIL_ACTIONS: readonly string[] = [
  's3:GetObject',
  's3:ListBucket',
  'dynamodb:Scan',
  'dynamodb:Query',
  'dynamodb:GetItem',
  'dynamodb:BatchGetItem',
  'secretsmanager:GetSecretValue',
  'ssm:GetParameter',
  'ssm:GetParameters',
  'ssm:GetParametersByPath',
  'kms:Decrypt',
  'rds:DownloadDBLogFilePortion',
  'lambda:GetFunction',
  'ec2:GetPasswordData',
];

export interface EscalationPath {
  id: string;
  title: string;
  /** Every listed action must be effectively allowed somewhere in the policy. */
  actions: readonly string[];
  description: string;
}

export const ESCALATION_PATHS: readonly EscalationPath[] = [
  {
    id: 'create-policy-version',
    title: 'Create a new default policy version',
    actions: ['iam:CreatePolicyVersion'],
    description:
      'With iam:CreatePolicyVersion the caller can write a new version of any attached policy (including an admin version) and set it as default in the same call.',
  },
  {
    id: 'set-default-policy-version',
    title: 'Switch to an older, broader policy version',
    actions: ['iam:SetDefaultPolicyVersion'],
    description:
      'Policies keep up to five versions. Switching the default to an older, broader version grants whatever that version allowed.',
  },
  {
    id: 'attach-policy',
    title: 'Attach a managed policy to a principal',
    actions: ['iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:AttachGroupPolicy'],
    description:
      'Attaching AdministratorAccess to the caller’s own user, group or an assumable role is a one-call path to admin.',
    // Any one of these is enough; expanded at check time.
  },
  {
    id: 'put-inline-policy',
    title: 'Write an inline policy on a principal',
    actions: ['iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:PutGroupPolicy'],
    description:
      'Inline policies can grant arbitrary permissions to the caller’s own user, group or an assumable role.',
  },
  {
    id: 'create-access-key',
    title: 'Create access keys for another user',
    actions: ['iam:CreateAccessKey'],
    description:
      'Creating an access key for a more privileged user lets the caller act as that user.',
  },
  {
    id: 'login-profile',
    title: 'Set or reset another user’s console password',
    actions: ['iam:CreateLoginProfile', 'iam:UpdateLoginProfile'],
    description:
      'Setting a console password on a privileged user grants console access as that user.',
  },
  {
    id: 'update-assume-role-policy',
    title: 'Rewrite a role’s trust policy',
    actions: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
    description: 'Editing a privileged role’s trust policy to trust the caller, then assuming it.',
  },
  {
    id: 'passrole-lambda',
    title: 'PassRole + Lambda',
    actions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    description:
      'Create a Lambda function with a privileged execution role and invoke it to run code as that role.',
  },
  {
    id: 'passrole-ec2',
    title: 'PassRole + EC2',
    actions: ['iam:PassRole', 'ec2:RunInstances'],
    description:
      'Launch an instance with a privileged instance profile and read its credentials from the metadata service.',
  },
  {
    id: 'passrole-cloudformation',
    title: 'PassRole + CloudFormation',
    actions: ['iam:PassRole', 'cloudformation:CreateStack'],
    description: 'Deploy a stack that creates IAM resources using a privileged service role.',
  },
  {
    id: 'passrole-glue',
    title: 'PassRole + Glue dev endpoint',
    actions: ['iam:PassRole', 'glue:CreateDevEndpoint'],
    description: 'A Glue dev endpoint gives an SSH shell running under the passed role.',
  },
  {
    id: 'passrole-sagemaker',
    title: 'PassRole + SageMaker notebook',
    actions: [
      'iam:PassRole',
      'sagemaker:CreateNotebookInstance',
      'sagemaker:CreatePresignedNotebookInstanceUrl',
    ],
    description:
      'A notebook instance exposes the passed role’s credentials to anyone who can open it.',
  },
  {
    id: 'assume-role-any',
    title: 'Assume any role',
    actions: ['sts:AssumeRole'],
    description:
      'sts:AssumeRole on every resource means the caller can assume any role whose trust policy admits them, including admin roles.',
    // Only fires when the resource is `*`; handled specially at check time.
  },
];

/** Operators recognised in a Condition block (without IfExists / set qualifiers). */
export const CONDITION_OPERATORS: ReadonlySet<string> = new Set([
  'StringEquals',
  'StringNotEquals',
  'StringEqualsIgnoreCase',
  'StringNotEqualsIgnoreCase',
  'StringLike',
  'StringNotLike',
  'NumericEquals',
  'NumericNotEquals',
  'NumericLessThan',
  'NumericLessThanEquals',
  'NumericGreaterThan',
  'NumericGreaterThanEquals',
  'DateEquals',
  'DateNotEquals',
  'DateLessThan',
  'DateLessThanEquals',
  'DateGreaterThan',
  'DateGreaterThanEquals',
  'Bool',
  'BinaryEquals',
  'IpAddress',
  'NotIpAddress',
  'ArnEquals',
  'ArnLike',
  'ArnNotEquals',
  'ArnNotLike',
  'Null',
]);

/** Condition keys that scope a public principal down to a known caller or source. */
export const PRINCIPAL_RESTRICTING_KEYS: readonly string[] = [
  'aws:SourceArn',
  'aws:SourceAccount',
  'aws:PrincipalOrgID',
  'aws:PrincipalOrgPaths',
  'aws:PrincipalAccount',
  'aws:PrincipalArn',
  'aws:SourceVpce',
  'aws:SourceVpc',
  'aws:SourceOwner',
];
