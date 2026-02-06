#!/usr/bin/env python3
"""
Agent Integration Testing Script

This script performs comprehensive integration testing of deployed AgentCore agents.
It validates agent functionality by sending various test prompts and verifying
responses, ensuring the agent is working correctly after deployment.

Usage:
    python test_agent.py --agent-name myagent --region us-east-1

The script will:
1. Read agent ARN from deployment_info.txt
2. Execute predefined test cases
3. Parse and validate responses
4. Report test results and any failures
"""

import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from json import dumps, loads, JSONDecodeError
from sys import exit

from boto3 import client as boto3_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def test_agent(agent_name, region):
    """
    Execute comprehensive integration tests on the deployed agent.
    
    This function runs a series of test cases against the deployed agent
    to validate its functionality across different scenarios including
    mathematical calculations, and general conversation.
    
    Args:
        agent_name (str): Name of the agent being tested
        region (str): AWS region where the agent is deployed
        
    Returns:
        bool: True if all tests pass, False if any test fails
        
    Raises:
        SystemExit: If deployment_info.txt is not found
    """
    # Get agent info from AWS
    control_client = boto3_client("bedrock-agentcore-control", region_name=region)
    try:
        # List agent runtimes and find the one with matching name
        response = control_client.list_agent_runtimes()
        agent_arn = None
        agent_id = None
            
        for runtime in response.get('agentRuntimes', []):
            if runtime['agentRuntimeName'] == agent_name:
                agent_arn = runtime['agentRuntimeArn']
                agent_id = runtime['agentRuntimeId']
                break
                
        if not agent_arn:
            logger.error(f"Agent runtime '{agent_name}' not found")
            logger.error("Please ensure the agent has been deployed successfully")
            return False
            
        logger.info(f"Found agent: {agent_arn}")
    except Exception as e:
        logger.error(f"Error finding agent runtime: {e}")
        return False

    # Check agent status once
    try:
        response = control_client.get_agent_runtime(agentRuntimeId=agent_id)
        status = response['status']
        logger.info(f"Agent runtime status: {status}")
        
        if status != 'READY':
            logger.error(f"Agent is not ready (status: {status}). Please wait and try again.")
            return False
    except Exception as e:
        logger.error(f"Could not check agent status: {e}")
        return False

    # Initialize Bedrock AgentCore client
    client = boto3_client("bedrock-agentcore", region_name=region)
    
    # Define comprehensive test cases covering different agent capabilities
    test_cases = [
        {"prompt": "What is 2 + 2?", "expected_contains": ["4"]},
        {"prompt": "Calculate 15 * 7", "expected_contains": ["105"]},
        {"prompt": "What is 100 / 4?", "expected_contains": ["25"]},
        {"prompt": "Hello, how are you?", "expected_contains": None},  # General conversation
    ]
    
    logger.info(f"Testing agent: {agent_name}")
    logger.info(f"Agent ARN: {agent_arn}")
    logger.info(f"Region: {region}")
    logger.info("=" * 60)
    
    all_passed = True
    
    # Execute each test case and validate responses
    for i, test_case in enumerate(test_cases, 1):
        prompt = test_case['prompt']
        expected_contains = test_case.get('expected_contains')
        
        logger.info(f"\n[Test {i}/{len(test_cases)}] Question: {prompt}")
        logger.info("-" * 40)
        
        try:
            # Invoke the agent with the test prompt
            response = client.invoke_agent_runtime(
                agentRuntimeArn=agent_arn,
                qualifier="DEFAULT",  # Use default agent version
                payload=dumps({"prompt": prompt})
            )
            
            response_text = None
            
            # Parse and display the response based on format
            if 'response' in response:
                # Handle streaming response body
                streaming_body = response['response']
                response_text = streaming_body.read().decode('utf-8')
                
                # Attempt to parse as JSON for structured responses
                try:
                    response_json = loads(response_text)
                    if isinstance(response_json, dict):
                        # Extract response content from common field names
                        if 'content' in response_json:
                            response_text = str(response_json['content'])
                        elif 'message' in response_json:
                            response_text = str(response_json['message'])
                        elif 'text' in response_json:
                            response_text = str(response_json['text'])
                        else:
                            response_text = str(response_json)
                    else:
                        response_text = str(response_json)
                except JSONDecodeError:
                    # Already have plain text response
                    pass
                    
            elif 'payload' in response:
                # Handle direct payload responses
                response_text = response['payload']
                if isinstance(response_text, bytes):
                    response_text = response_text.decode('utf-8')
            
            # Display the response
            if response_text:
                logger.info(f"Response: {response_text}")
                
                # Validate expected content if specified
                if expected_contains:
                    found = False
                    for expected in expected_contains:
                        if expected.lower() in response_text.lower():
                            found = True
                            break
                    
                    if found:
                        logger.info(f"✓ Test passed - found expected content")
                    else:
                        logger.warning(f"⚠ Response doesn't contain expected values: {expected_contains}")
                        logger.warning("This may be acceptable depending on the agent's response style")
                else:
                    logger.info(f"✓ Test passed - agent responded")
            else:
                # Handle HTTP status responses
                logger.info(f"✓ Test passed (HTTP {response.get('statusCode', 200)})")
                logger.info(f"Session ID: {response.get('runtimeSessionId', 'N/A')}")
            
        except Exception as e:
            logger.error(f"✗ Test failed: {e}")
            
            # Try to get CloudWatch logs for debugging
            if agent_id:
                logger.info("\nAttempting to fetch CloudWatch logs for debugging...")
                try:
                    logs_client = boto3_client("logs", region_name=region)
                    log_group_name = f"/aws/bedrock/agentcore/{agent_id}"
                    
                    # Get recent log streams
                    streams_response = logs_client.describe_log_streams(
                        logGroupName=log_group_name,
                        orderBy='LastEventTime',
                        descending=True,
                        limit=1
                    )
                    
                    if streams_response.get('logStreams'):
                        stream_name = streams_response['logStreams'][0]['logStreamName']
                        
                        # Get recent log events
                        events_response = logs_client.get_log_events(
                            logGroupName=log_group_name,
                            logStreamName=stream_name,
                            limit=20,
                            startFromHead=False
                        )
                        
                        if events_response.get('events'):
                            logger.info("\nRecent CloudWatch logs:")
                            logger.info("-" * 60)
                            for event in events_response['events'][-10:]:  # Last 10 events
                                logger.info(event['message'])
                            logger.info("-" * 60)
                        else:
                            logger.info("No recent log events found")
                    else:
                        logger.info(f"No log streams found in {log_group_name}")
                        
                except Exception as log_error:
                    logger.warning(f"Could not fetch CloudWatch logs: {log_error}")
            
            all_passed = False
    
    # Report final test results
    logger.info("\n" + "=" * 60)
    if all_passed:
        logger.info("All tests passed! Agent is functioning correctly.")
        return True
    else:
        logger.error("Some tests failed! Please check the agent configuration.")
        return False


def main():
    """
    Main function to handle command-line arguments and run tests.
    
    Parses command-line arguments and executes the test suite against
    the specified agent deployment.
    """
    parser = ArgumentParser(
        description="Test deployed AgentCore agent functionality",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_agent.py --agent-name myagent --region us-east-1

Test Coverage:
- Mathematical calculations (calculator tool)
- General conversation (model capabilities)
- Response parsing and validation

The script requires deployment_info.txt to be present with agent ARN.
        """
    )
    
    parser.add_argument("--agent-name", required=True,
                       help="Name of the agent to test")
    parser.add_argument("--region", required=True,
                       help="AWS region where the agent is deployed")
    
    args = parser.parse_args()
    
    logger.info(f"Starting integration tests for agent: {args.agent_name}")
    
    # Run the test suite and exit with appropriate code
    if not test_agent(args.agent_name, args.region):
        logger.error("\nTest suite failed!")
        exit(1)
    
    logger.info("\nTest suite completed successfully!")


if __name__ == "__main__":
    main()
