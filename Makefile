.PHONY: install dev web run eval test tf-init tf-validate tf-plan deploy

PROJECT_ID ?= $(GOOGLE_CLOUD_PROJECT)
LOCATION ?= us-central1

install:
	python3 -m pip install -e ".[dev]"

# Launch interactive ADK developer UI
web:
	adk web .

# Run interactive CLI session via ADK CLI
run:
	adk run sentinel_sre_agent

# Execute ADK golden dataset evaluation & deterministic regression suite
eval:
	python3 -m unittest discover -s tests -p "test_*.py" -v
	adk eval sentinel_sre_agent tests/eval/sentinel_golden.evalset.json --config_file_path tests/eval/eval_config.json

# Run unit & integration regression harness
test:
	python3 -m unittest discover -s tests -p "test_*.py" -v

# Deploy agent to Vertex AI Agent Engine using ADK CLI
deploy:
	adk deploy agent_engine \
		--project=$(PROJECT_ID) \
		--region=$(LOCATION) \
		--display_name="Sentinel SRE Multi-Agent System" \
		sentinel_sre_agent

# Infrastructure as Code (Terraform) lifecycle
tf-init:
	terraform -chdir=terraform init -backend=false

tf-validate:
	terraform -chdir=terraform validate

tf-plan:
	terraform -chdir=terraform plan -var="project_id=$(PROJECT_ID)" -var="region=$(LOCATION)"
