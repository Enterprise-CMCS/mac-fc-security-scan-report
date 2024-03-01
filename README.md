# macfc-security-scan-report
This GitHub Action script is designed to create Jira tickets for vulnerabilities detected during security scans. It supports currently supports scans run with Snyk. The script parses the scan output, identifies vulnerabilities, and creates Jira tickets for each unique vulnerability found.

# Inputs
The script expects the following inputs:
```
jira-host:                   The host URL of your Jira instance.
jira-username:               The username used to authenticate with Jira.
jira-token:                  The token or password used to authenticate with Jira.
jira-project-key:            The Jira project key where the tickets will be created.
jira-title-prefix:           The prefix to be added to the Jira ticket summary.
jira-issue-type:             The Jira issue type for the created tickets.
jira-labels:                 Labels to be applied to the created Jira tickets (comma-separated).
jira-custom-field-key-value: A JSON string containing key-value pairs of custom fields and their values in Jira.
assign-jira-ticket-to:       The accountID of a user to assigne a ticket to.
scan-output-path:            The path to the scan output file.
snyk-test-type:              The type of Snyk scan being run. Accepts 'open-source', 'iac', or 'container'. Defaults to 'open-source'.
min-severity:                The minimum severity level a vulnerability must have for a Jira ticket to be created. Accepts 'low', 'medium', 'high', 'critical'.
```
# Usage

To use this GitHub Action script, you can create a workflow file (e.g., .github/workflows/security-scan.yml) in your repository with the following content:
```
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
        uses: Enterprise-CMCS/security-hub-visibility@v1.0.2
        with:
          jira-host: ${{ secrets.JIRA_HOST }}
          jira-username: ${{ secrets.JIRA_USERNAME }}
          jira-token: ${{ secrets.JIRA_TOKEN }}
          jira-project-key: ABC  # replace with your project key
          jira-title-prefix: "Security Vulnerability -"  # customize as needed
          jira-issue-type: Bug  # customize as needed
          jira-labels: security, vulnerability  # customize as needed
          jira-custom-field-key-value: '{"customFieldKey": "customValue"}'  # customize as needed
          assign-jira-ticket-to: "668976660"
          scan-output-path: scan-output.json
```

Ensure that you have the required secrets (JIRA_HOST, JIRA_USERNAME, and JIRA_TOKEN) configured in your repository's settings so that they can be accessed by the Action script.

The workflow configuration assumes that you are running the security scan command and saving the output to a file named scan-output.json. Adjust the command and file name according to your specific scan tool and configuration. For more information on how to implement a Snyk scan and use it in conjuction with this action, please view [`SNYK.md`](./SNYK.md).