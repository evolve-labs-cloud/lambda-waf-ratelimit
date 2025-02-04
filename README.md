# WAF Rate Limit Monitor

This AWS Lambda function monitors WAF rate limit triggers, automatically blocks offending IP addresses, and sends notifications to Slack. The function analyzes CloudWatch Logs to identify IPs that exceed rate limits, adds them to a WAF IP set, and notifies the team through Slack.

## Features

- Monitors WAF rate limit rule triggers in real-time
- Automatically identifies and blocks IPs exceeding rate limits
- Updates WAF IP set with new blocked IPs
- Sends detailed Slack notifications
- Configurable thresholds and monitoring periods
- Comprehensive error handling and logging

## Prerequisites

- AWS Lambda environment
- CloudWatch Log Group containing WAF logs
- WAF v2 IP Set configured
- Slack workspace with a bot token and channel

## Environment Variables

| Variable | Type | Description |
|----------|------|-------------|
| LOG_GROUP_NAME | string | CloudWatch Log Group name containing WAF logs |
| QUERY_TIME_RANGE_MINUTES | integer | Time range in minutes for analyzing logs |
| REQUEST_THRESHOLD | integer | Threshold for number of requests to trigger blocking |
| IP_SET_ID | string | WAF IP Set ID for storing blocked IPs |
| IP_SET_NAME | string | Name of the WAF IP Set |
| IP_SET_SCOPE | string | Scope of the IP Set (REGIONAL or CLOUDFRONT) |
| SLACK_BOT_TOKEN | string | Slack Bot User OAuth Token |
| SLACK_CHANNEL_ID | string | Slack Channel ID for notifications |

## CloudWatch Logs Query

The function uses the following query to identify IPs exceeding the rate limit:

```sql
fields httpRequest.clientIp, httpRequest.country, httpRequest.uri, ja3Fingerprint, @message, @timestamp, terminatingRuleId as rule
| filter rule like "rate-limit"
| stats count(*) as requestCount by httpRequest.clientIp
| filter requestCount > 5
```

## Function Flow

1. **Environment Validation**
   - Validates all required environment variables
   - Ensures correct variable types

2. **Log Analysis**
   - Executes CloudWatch Logs query
   - Identifies IPs exceeding rate limits
   - Extracts request counts and details

3. **IP Set Management**
   - Retrieves current WAF IP Set
   - Converts IPs to CIDR notation
   - Updates IP Set with new blocked IPs

4. **Notification**
   - Formats blocked IP details
   - Sends notifications to Slack
   - Includes request counts and timestamps

## Response Format

Successful execution returns:
```json
{
    "statusCode": 200,
    "body": {
        "message": "Processed X IPs, newly blocked Y IPs",
        "newly_blocked_ips": ["ip1", "ip2"],
        "total_ips_checked": N,
        "slack_notification": "success"
    }
}
```

Error response:
```json
{
    "statusCode": 500,
    "body": {
        "error": "Error message"
    }
}
```

## IAM Permissions Required

The Lambda execution role needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:StartQuery",
                "logs:GetQueryResults",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": [
                "arn:aws:logs:*:*:log-group:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "wafv2:ListIPSets",
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": "*"
        }
    ]
}
```

## Error Handling

The function includes comprehensive error handling for:
- Missing/invalid environment variables
- CloudWatch Logs query failures
- WAF IP Set update failures
- Slack notification errors

All errors are logged to CloudWatch Logs with detailed information.

## Deployment

1. Package the Lambda function with dependencies
2. Configure environment variables
3. Set up IAM role with required permissions
4. Configure CloudWatch Events trigger (recommended every 5 minutes)

## Monitoring

The function logs extensively to CloudWatch Logs. Monitor:
- Function execution status
- Number of IPs processed and blocked
- Query execution time
- IP Set update status
- Slack notification delivery

## Limitations

- Maximum query time range is limited by CloudWatch Logs query timeout
- IP Set has a maximum capacity (check AWS quotas)
- Rate limiting depends on accurate CloudWatch Logs delivery

## Contributing

Please submit issues and pull requests for any improvements.

## License

[Specify your license here]
