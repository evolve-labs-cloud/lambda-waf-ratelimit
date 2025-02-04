import boto3
import time
import os
import json
import urllib.request
import urllib.parse
import logging
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Tuple

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
logs_client = boto3.client('logs')
wafv2_client = boto3.client('wafv2')

def validate_environment() -> Dict[str, Any]:
    """
    Validate and return environment variables
    """
    required_vars = {
        'LOG_GROUP_NAME': str,
        'QUERY_TIME_RANGE_MINUTES': int,
        'REQUEST_THRESHOLD': int,
        'IP_SET_ID': str,
        'IP_SET_NAME': str,
        'IP_SET_SCOPE': str,
        'SLACK_BOT_TOKEN': str,
        'SLACK_CHANNEL_ID': str
    }
    
    config = {}
    missing = []
    
    for var, var_type in required_vars.items():
        if var not in os.environ:
            missing.append(var)
        else:
            try:
                config[var] = var_type(os.environ[var])
            except ValueError as e:
                raise ValueError(f"Invalid {var}: {str(e)}")
    
    if missing:
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")
        
    return config

def execute_query(start_time: int, end_time: int, query: str, max_retries: int = 3) -> List[Dict]:
    """
    Execute CloudWatch Logs query with retries
    """
    logger.info(f"Executing query from {start_time} to {end_time}")
    logger.info(f"Query: {query}")

    try:
        start_response = logs_client.start_query(
            logGroupName=CONFIG['LOG_GROUP_NAME'],
            startTime=start_time,
            endTime=end_time,
            queryString=query
        )
        query_id = start_response['queryId']
        logger.info(f"Started query with ID: {query_id}")

        retries = 0
        while retries < max_retries:
            response = logs_client.get_query_results(queryId=query_id)
            status = response['status']
            logger.info(f"Query status: {status}")

            if status == 'Complete':
                logger.info(f"Query completed with {len(response['results'])} results")
                return response['results']
            elif status in ['Failed', 'Cancelled']:
                raise Exception(f"Query failed with status: {status}")

            retries += 1
            sleep_time = min(2 ** retries, 10)
            time.sleep(sleep_time)

        raise TimeoutError("Query execution timed out")

    except Exception as e:
        logger.error(f"Query execution failed: {str(e)}")
        raise

def extract_ips_to_block(query_results: List[Dict]) -> Tuple[List[str], List[Dict]]:
    """
    Extract IPs and their details from query results
    """
    logger.info(f"Processing {len(query_results)} query results")
    ips = []
    details = []

    for result in query_results:
        logger.info(f"Processing result: {json.dumps(result)}")
        ip = next((item['value'] for item in result if item['field'] == 'httpRequest.clientIp'), None)
        count = next((item['value'] for item in result if item['field'] == 'requestCount'), '0')

        if ip:
            logger.info(f"Found IP {ip} with count {count}")
            ips.append(ip)
            details.append({
                'ip': ip,
                'count': count
            })

    logger.info(f"Found {len(ips)} IPs to block")
    return ips, details

def update_ip_set(ips_to_block: List[str]) -> Tuple[bool, List[str]]:
    """
    Update WAF IP set with new IPs to block
    Returns a tuple of (success, list of newly added IPs)
    """
    try:
        logger.info(f"Getting current IP set: {CONFIG['IP_SET_NAME']}")
        
        # Get current IP set
        ip_set = wafv2_client.get_ip_set(
            Name=CONFIG['IP_SET_NAME'],
            Scope=CONFIG['IP_SET_SCOPE'],
            Id=CONFIG['IP_SET_ID']
        )
        logger.info("Successfully retrieved IP set")
        
        # Convert IPs to CIDR format
        new_ips = set(f"{ip}/32" for ip in ips_to_block)
        logger.info(f"New IPs to add (in CIDR format): {new_ips}")
        
        # Get current IPs
        current_ips = set(ip_set['IPSet']['Addresses'])
        logger.info(f"Current IPs in set: {current_ips}")
        
        # Find actually new IPs
        actually_new_ips = new_ips - current_ips
        logger.info(f"Actually new IPs to add: {actually_new_ips}")
        
        if not actually_new_ips:
            logger.info("No new IPs to add - all IPs already blocked")
            return True, []
        
        # Combine IPs and update
        updated_ips = list(current_ips.union(new_ips))
        logger.info(f"Updating IP set to {len(updated_ips)} IPs")
        
        wafv2_client.update_ip_set(
            Name=CONFIG['IP_SET_NAME'],
            Scope=CONFIG['IP_SET_SCOPE'],
            Id=CONFIG['IP_SET_ID'],
            Description='Auto-updated by rate limit Lambda',
            Addresses=updated_ips,
            LockToken=ip_set['LockToken']
        )
        logger.info("Successfully updated IP set")
        
        # Convert CIDR back to IP for return value
        new_ip_list = [ip.replace('/32', '') for ip in actually_new_ips]
        return True, new_ip_list
        
    except Exception as e:
        logger.error(f"Failed to update IP set: {str(e)}")
        return False, []

def send_slack_notification(ips_blocked: List[str], details: List[Dict]) -> Tuple[bool, str]:
    """
    Send Slack notification about blocked IPs
    """
    try:
        logger.info("Preparing Slack notification")
        message = (
            "🚨 *WAF IP Block Alert* 🚨\n"
            f"{len(ips_blocked)} IP(s) exceeded rate limit and have been blocked:\n\n"
        )
        
        for detail in details:
            message += (
                f"• *IP:* {detail['ip']}\n"
                f"  *Request Count:* {detail['count']}\n\n"
            )
            
        slack_message = {
            'channel': CONFIG['SLACK_CHANNEL_ID'],
            'text': message,
            'mrkdwn': True
        }
        
        logger.info(f"Sending to Slack channel: {CONFIG['SLACK_CHANNEL_ID']}")
        
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'Authorization': f"Bearer {CONFIG['SLACK_BOT_TOKEN']}"
        }
        
        encoded_data = json.dumps(slack_message).encode('utf-8')
        
        req = urllib.request.Request(
            'https://slack.com/api/chat.postMessage',
            data=encoded_data,
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            response_body = json.loads(response.read().decode('utf-8'))
            if response_body.get('ok'):
                logger.info("Successfully sent Slack notification")
                return True, ""
            else:
                error = response_body.get('error', 'Unknown error')
                logger.error(f"Slack API error: {error}")
                return False, f"Slack API error: {error}"
                
    except Exception as e:
        error_msg = f"Failed to send Slack notification: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

def lambda_handler(event: Dict, context: Any) -> Dict:
    """
    Main Lambda handler
    """
    try:
        logger.info("=== Lambda Execution Start ===")
        
        # Initialize configuration
        global CONFIG
        CONFIG = validate_environment()

        # Set query time range
        end_time = int(time.time())
        start_time = end_time - (CONFIG['QUERY_TIME_RANGE_MINUTES'] * 60)
        
        # Execute query
        query = """
        fields httpRequest.clientIp, httpRequest.country, httpRequest.uri, ja3Fingerprint, @message, @timestamp, terminatingRuleId as rule
        | filter rule like "rate-limit"
        | stats count(*) as requestCount by httpRequest.clientIp
        | filter requestCount > 5
        """
        
        query_results = execute_query(start_time, end_time, query)
        ips_to_block, ip_details = extract_ips_to_block(query_results)

        if not ips_to_block:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    "message": "No IPs to block",
                    "timeRange": {
                        "start": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start_time)),
                        "end": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(end_time))
                    }
                })
            }

        # Update WAF IP set
        update_success, newly_blocked_ips = update_ip_set(ips_to_block)
        if not update_success:
            return {
                'statusCode': 500,
                'body': json.dumps({
                    "error": "Failed to update WAF IP set",
                    "ips": ips_to_block
                })
            }

        # Only send Slack notification if there are new IPs
        if newly_blocked_ips:
            # Filter details to only include newly blocked IPs
            new_ip_details = [d for d in ip_details if d['ip'] in newly_blocked_ips]
            slack_success, error_message = send_slack_notification(newly_blocked_ips, new_ip_details)
            notification_status = "success" if slack_success else f"failed: {error_message}"
        else:
            notification_status = "skipped - no new IPs"

        return {
            'statusCode': 200,
            'body': json.dumps({
                "message": f"Processed {len(ips_to_block)} IPs, newly blocked {len(newly_blocked_ips)} IPs",
                "newly_blocked_ips": newly_blocked_ips,
                "total_ips_checked": len(ips_to_block),
                "slack_notification": notification_status
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                "error": str(e)
            })
        }
    finally:
        logger.info("=== Lambda Execution Complete ===")
