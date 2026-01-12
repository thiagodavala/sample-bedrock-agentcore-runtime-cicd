# AgentCore CI/CD Pipeline

**Automated deployment of Strand Agents to Amazon Bedrock AgentCore Runtime using GitHub Actions**

This repository provides a complete CI/CD solution for deploying AI agents built with the Strands framework to AWS Bedrock AgentCore Runtime using boto3 API calls with enhanced security and container optimization.

## What This Solution Does

### Agent Capabilities
The deployed agent can:
1. **Natural Conversations**: Powered by Claude Sonnet 4 model
2. **Mathematical Calculations**: Perform arithmetic operations using calculator tool
3. **Guardrail Protection**: Optional Bedrock guardrails for content filtering
4. **Tool Integration**: Easily add new tools and capabilities

## Architecture Overview

![AgentCore CI/CD Architecture](images/architecture.png)

### Detailed Steps:
1. A developer commits code changes from their local repository to the GitHub repository. In this solution, the GitHub Action is triggered automatically. 
2. The GitHub Action triggers the build stage. 
3. GitHub's OpenID Connect (OIDC) uses tokens to authenticate with AWS and access resources.
4. GitHub Actions invokes the command to build and push the agent container image to Amazon ECR directly from the Dockerfile. 
5. AWS Inspector triggers an advanced security scan when the image is uploaded. The pipeline will halt if it identifies any vulnerabilities in the container image. 
6. AgentCore Runtime instance will be created using the container image. 
7. The agent can further query the Bedrock Model and invoke tools as per its configuration.

## Quick Start Guide

### Prerequisites
- AWS Account with appropriate permissions
- GitHub repository
- Python 3.12+ (for local development)

### 1. Clone and Setup
```bash
git clone https://github.com/aws-samples/sample-bedrock-agentcore-runtime-cicd
cd sample-bedrock-agentcore-runtime-cicd
```

### 2. Configure AWS Authentication
Reference Documentation: https://aws.amazon.com/blogs/security/use-iam-roles-to-connect-github-actions-to-actions-in-aws/

```bash
# Set up OIDC authentication (run once)
python scripts/setup_oidc.py --github-repo <your-username>/<your-repo-name>
```

### 3. Add GitHub Secrets
In your GitHub repository settings, add:
- **Secret Name**: `AWS_ROLE_ARN`
- **Secret Value**: (ARN output from setup_oidc.py)

### 4. Deploy Your Agent
```bash
# Simply push to main branch
git add .
git commit -m "Deploy my agent"
git push origin main
```

In this code sample, the pipeline trigger is configured for manual execution via workflow_dispatch. To enable automated pipeline execution, you can modify the trigger to use on: push or on: pull_request based on your specific use case.

The pipeline will:
1. **Validate**: Code formatting, linting, and dependency checks
2. **Build & Deploy**: ARM64-compatible container with security scanning
3. **Test**: Integration tests via separate workflow (manual trigger)
4. **Cleanup**: Targeted ECR image cleanup (keeps 9 most recent images)

## Project Structure

```
├── agents/                          # Agent implementation
│   ├── strands_agent.py            # Main agent code (Claude + calculator tool)
│   └── requirements.txt            # Python dependencies
├── scripts/                        # Deployment automation
│   ├── setup_oidc.py              # AWS OIDC configuration
│   ├── create_iam_role.py         # IAM role creation
│   ├── create_guardrail.py        # Bedrock guardrail setup
│   ├── deploy_agent.py            # Agent deployment with container URI
│   ├── test_agent.py              # Integration testing
│   └── cleanup_ecr.py             # Targeted ECR image cleanup
├── .github/workflows/
│   ├── deploy-agentcore.yml       # Main CI/CD pipeline
│   └── test-agent.yml             # Manual testing workflow
├── Dockerfile                      # Optimized container with security features
└── README.md                      # This file
```

## Customizing Your Agent

### 1. Modifying Agent Behavior
Edit `agents/strands_agent.py` to customize your agent:

```python
# Add new tools
@tool
def my_custom_tool():
    """Description of what this tool does"""
    return "Tool response"

# Update system prompt
agent = Agent(
    model=model,
    tools=[calculator, my_custom_tool],  # Add your tool
    system_prompt="Your custom agent personality and instructions"
)
```

### 2. Environment Configuration
Modify deployment settings in `.github/workflows/deploy-agentcore.yml`:
```yaml
env:
  AWS_REGION: us-east-1  # Change region if needed

# In the Set environment variables step:
AGENT_NAME: "strands_agent"  # Customize agent name
ECR_REPOSITORY: "${AGENT_NAME}"  # ECR repository name
```

## Manual Operations

### 1. Local Testing
```bash
# Install dependencies
pip install -r agents/requirements.txt
pip install pytest black isort flake8
```

### 2. Manual Deployment
```bash
# Create IAM role
python scripts/create_iam_role.py --agent-name myagent --region us-east-1

# Create Bedrock guardrail (optional)
python scripts/create_guardrail.py --region us-east-1

# Deploy agent with container URI (auto-update enabled by default)
python scripts/deploy_agent.py \
  --agent-name myagent \
  --region us-east-1 \
  --container-uri "123456789012.dkr.ecr.us-east-1.amazonaws.com/myagent:latest" \
  --auto-update-on-conflict

# Test deployment
python scripts/test_agent.py --agent-name myagent --region us-east-1

# Clean up old ECR images
python scripts/cleanup_ecr.py \
  --region us-east-1 \
  --repository-name myagent \
  --keep-count 5
```

## Pipeline Architecture

### Workflows
1. **deploy-agentcore.yml**: Main CI/CD pipeline (triggered on push to main)
2. **test-agent.yml**: Manual testing workflow (workflow_dispatch)

### Pipeline Stages

#### 1. **Validation Stage**
- Code formatting checks
- Linting
- Dependency validation

#### 2. **Deployment Stage**
- AWS authentication via OIDC
- IAM role creation/update
- Cross-platform container build
- AgentCore Runtime deployment
- ECR security scanning setup

#### 3. **Testing Stage**
- Agent functionality validation
- Response quality checks
- Integration test execution

#### 4. **Cleanup Stage**
- Targeted ECR image cleanup (specific repository only)
- Retention policy (keeps 5 most recent images)
- Cost optimization

## Security Features

#### 1. **Authentication & Authorization**
- **OIDC Integration**: Keyless authentication between GitHub and AWS
- **Least Privilege**: IAM roles with minimal required permissions

#### 2. **Container Security**
- **Vulnerability Scanning**: Automatic ECR enhanced scanning on push
- **Base Image Pinning**: SHA256-pinned Python base image for reproducibility
- **Non-root Execution**: Container runs as non-privileged user
- **Health Checks**: Built-in container health monitoring

#### 3. **Network Security**
- **Encryption**: Data encryption in transit and at rest
- **Access Logging**: Logging via AWS CloudWatch

## Security Recommendations

#### 1. **Input Validation**
This deployment solution focuses on CI/CD automation and does not provide mechanisms for users to submit prompts directly to deployed agents. For production deployments, implement proper validation of `payload.get("prompt")` to handle None or invalid input types before processing user requests.

#### 2. **Bedrock Guardrails**
The pipeline automatically creates baseline Bedrock guardrails for content filtering. Review and customize guardrail policies based on your use case requirements.

#### 3. **Container Security**
- Base image is pinned to specific SHA256 hash for reproducible builds
- Container runs as non-root user for enhanced security
- ECR enhanced scanning detects vulnerabilities automatically

#### 4. **Network Security**
- Agent runtime uses PUBLIC network mode (customize as needed)
- All communications encrypted in transit via HTTPS/TLS

## Key Features & Optimizations

This implementation provides enterprise-grade CI/CD with security and cost optimizations:

### **Direct API Control**
- Uses `bedrock-agentcore-control` boto3 client for runtime management
- Custom Docker buildx for ARM64 container creation
- Direct ECR repository creation and image pushing
- Enhanced error handling and deployment process control

### **Security Enhancements**
- SHA256-pinned base images for reproducible builds
- Non-root container execution
- ECR enhanced vulnerability scanning
- Bedrock guardrails integration
- OIDC authentication (no long-lived credentials)

### **Cost Optimization**
- Targeted ECR cleanup
- Configurable image retention policies
- ARM64 architecture for better price-performance
- Efficient multi-stage container builds

### **Operational Excellence**
- Separate testing workflow for manual validation
- Comprehensive logging and error handling
- Auto-update capabilities for existing agents
- Health checks and monitoring integration

## Additional Resources

- [AWS Bedrock AgentCore Documentation](https://docs.aws.amazon.com/bedrock-agentcore/)
- [Bedrock AgentCore Control API Reference](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/)
- [Strands Framework Documentation](https://strands.ai/docs)
- [GitHub OIDC Setup Guide](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Docker Buildx Multi-platform Builds](https://docs.docker.com/buildx/working-with-buildx/)

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

## Contributors

- Prafful Gupta
- Anshu Bathla