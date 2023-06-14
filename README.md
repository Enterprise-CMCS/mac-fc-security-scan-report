# macfc-security-scan-report
This GitHub Action script is designed to create Jira tickets for vulnerabilities detected during security scans. It supports two types of scans: Zap and Snyk. The script parses the scan output, identifies vulnerabilities, and creates Jira tickets for each unique vulnerability found.

Inputs
The following inputs are required for the script to run:

jira-host: The hostname of the Jira instance.
jira-username: The username for authenticating with the Jira instance.
jira-token: The token or password for authenticating with the Jira instance.
scan-type: The type of security scan to process. Valid options are "zap" and "snyk".
zap-risk-code (only for Zap scans): The minimum risk code for vulnerabilities to be considered.
jira-project-key: The key of the Jira project where the tickets will be created.
jira-title-prefix: A prefix to be added to the Jira ticket summary.
jira-issue-type: The issue type to be assigned to the created Jira tickets.
jira-labels: Comma-separated labels to be added to the Jira tickets.
jira-custom-field-key-value: A JSON string representing custom field key-value pairs to be set on the Jira tickets.
scan-output-path: The path to the output file of the security scan.

Usage
To use this GitHub Action script, you can create a workflow file (e.g., .github/workflows/security-scan.yml) in your repository with the following content:

name: Security Scan

on:
  push:
    branches:
      - main

jobs:
  scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
        
      - name: Run security scan
        # Replace `your-scan-command` with the command to run your security scan
        run: your-scan-command > scan-output.json
      
      - name: Create Jira tickets
        uses: your-username/your-repo@your-tag
        with:
          jira-host: ${{ secrets.JIRA_HOST }}
          jira-username: ${{ secrets.JIRA_USERNAME }}
          jira-token: ${{ secrets.JIRA_TOKEN }}
          scan-type: zap  # or snyk
          zap-risk-code: 2  # (optional, only for Zap scans)
          jira-project-key: ABC  # replace with your project key
          jira-title-prefix: "Security Vulnerability -"  # customize as needed
          jira-issue-type: Bug  # customize as needed
          jira-labels: security, vulnerability  # customize as needed
          jira-custom-field-key-value: '{"customFieldKey": "customValue"}'  # customize as needed
          scan-output-path: scan-output.json

Make sure to replace your-username/your-repo@your-tag with the actual GitHub repository and tag where your Action script is located.

Ensure that you have the required secrets (JIRA_HOST, JIRA_USERNAME, and JIRA_TOKEN) configured in your repository's settings so that they can be accessed by the Action script.

The workflow configuration assumes that you are running the security scan command and saving the output to a file named scan-output.json. Adjust the command and file name according to your specific scan tool and configuration