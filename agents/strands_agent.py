"""
This module defines a conversational AI agent that can perform calculations
using the Strands framework.
"""

import logging
import sys

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from strands_tools import calculator

# Configure logging to output to both stdout and stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
    force=True,
)

# Add stderr handler as well
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)

logger = logging.getLogger(__name__)
logger.addHandler(stderr_handler)

# Also configure root logger to ensure all logs are captured
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(stderr_handler)

# Initialize the Bedrock AgentCore application
app = BedrockAgentCoreApp()

logger.info("Initializing Strands Agent...")

# Configure the model for the agent with guardrail
# Using Claude 3.5 Haiku - fast, cost-effective, available by default
model_id = "us.anthropic.claude-3-5-haiku-20241022-v1:0"
logger.info(f"Using model: {model_id}")

# Load guardrail ID if available
guardrail_config = None
try:
    with open("guardrail_id.txt", "r", encoding="utf-8") as f:
        guardrail_id = f.read().strip()
        if guardrail_id:
            guardrail_config = {
                "guardrailIdentifier": guardrail_id,
                "guardrailVersion": "1",
            }
            logger.info(f"Loaded guardrail: {guardrail_id}")
except FileNotFoundError:
    logger.info("No guardrail file found - running without guardrail")
except Exception as e:
    logger.error(f"Error loading guardrail: {e}")

try:
    model = BedrockModel(model_id=model_id, guardrail=guardrail_config)
    logger.info("Model initialized successfully")
except Exception as e:
    logger.error(f"Error initializing model: {e}")
    raise

# Create the agent with tools and system prompt
try:
    agent = Agent(
        model=model,
        tools=[calculator],
        system_prompt="You're a helpful assistant. You can do simple math calculation.",
    )
    logger.info("Agent initialized successfully")
except Exception as e:
    logger.error(f"Error initializing agent: {e}")
    raise


@app.entrypoint
def strands_agent_bedrock(payload):
    """
    Main entrypoint for the Bedrock AgentCore Runtime.

    This function is called by AWS Bedrock AgentCore when the agent receives
    a request. It processes the user input and returns the agent's response.

    Args:
        payload (dict): Request payload containing user input
                       Expected format: {"prompt": "user question"}

    Returns:
        str: The agent's text response to the user's prompt
    """
    try:
        logger.info(f"Received payload: {payload}")

        # Extract the user's prompt from the payload
        user_input = payload.get("prompt")

        if not user_input:
            logger.error("No prompt found in payload")
            return "Error: No prompt provided"

        logger.info(f"Processing prompt: {user_input}")

        # Process the input through the agent
        # (handles tool selection and model inference)
        response = agent(user_input)

        logger.info(f"Agent response: {response}")

        # Extract and return the text content from the response
        result = response.message["content"][0]["text"]
        logger.info(f"Returning result: {result}")
        return result

    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        return f"Error: {str(e)}"


if __name__ == "__main__":
    # Run the application on 0.0.0.0 to accept connections from any interface
    # This is required for Docker containers
    logger.info("Starting Bedrock AgentCore application on 0.0.0.0:8080...")
    app.run(host="0.0.0.0", port=8080)
