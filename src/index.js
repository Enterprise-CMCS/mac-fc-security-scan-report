const fs = require('fs');
const axios = require('axios').default; 
const core = require('@actions/core');
const path = require('path');

// Install dependencies 
const installDependency = (dependency) => {
  core.startGroup(`Installing ${dependency}`);
  const installResult = require('child_process').spawnSync('npm', ['install', dependency], { stdio: 'inherit' });
  core.endGroup();
  return installResult;
};

const installDependencies = (dependencies) => {
  dependencies.forEach(dependency => installDependency(dependency));
};

const token = core.getInput('jira-token');
const baseURL = `https://${core.getInput('jira-host')}`;
const headers = {
  'Content-Type': 'application/json',
};

let jira;
const isJiraEnterprise = core.getInput('is_jira_enterprise');

if (isJiraEnterprise === 'true') {
  jira = axios.create({
    baseURL,
    headers: {
      ...headers,
      Authorization: `Bearer ${token}`,
    },
  });
} else if (isJiraEnterprise === 'false'){
  const username = core.getInput('jira-username');
  const password = core.getInput('jira-token');

  jira = axios.create({
    baseURL,
    auth: {
      username,
      password,
    },
    headers,
  });
} else {
  console.error('Invalid jira instance type. Please provide "true" if the jira instance is enterprise version or "false" otherwise.');
  process.exit(1);
}


// Function to check if the user exists using the Jira REST API
async function doesUserExist(username) {
  try { 
    let response;

    if (isJiraEnterprise === 'true') {
      response = await jira.get(`/rest/api/2/user?username=${username}`);
    } else if (isJiraEnterprise === 'false') {
      response = await jira.get(`/rest/api/2/user?accountId=${username}`);
    } else {
      console.log('Invalid isJiraEnterprise value:', isJiraEnterprise);
      process.exit(1);
    }

    if (response.status === 200) {
      // User exists (status code 200 OK)
      return true;
    } else if (response.status === 404) {
      // User does not exist (status code 404 Not Found)
      return false;
    } else {
      // Handle other response statuses if needed
      throw new Error(`Unexpected response status: ${response.status} ${response.statusText}`);
    }
  } catch (err) {
    console.error(err);
    return false; // Return false if there was an error during the HTTP request
  }
}

try {
  const scanType = core.getInput('scan-type');
  if (scanType === 'zap') {
    // Parse the JSON file from Zap scan
    function parseZapOutput(jsonData) {
      let vulnerabilities = [];
      if (jsonData) {
        try {
          const data = JSON.parse(jsonData);
          for (const site of data.site) {
            for (const alert of site.alerts) {
              let instanceDescription = '\nInstances:\n';
              for (const instance of alert.instances) {
                const { uri, method, param, attack, evidence, otherinfo } = instance;
                instanceDescription += `URI: ${uri}\nMethod: ${method}\nParam: ${param}\nAttack: ${attack}\nEvidence: ${evidence}\nOtherInfo: ${otherinfo}\n\n`;
              }
              if (alert.riskcode >= parseInt(core.getInput('zap-risk-code'))) {
                vulnerabilities.push({
                  name: alert.name.concat(': ', data.site[0]['@host']).replace(/-/g, ''),
                  solution: alert.solution.replace(/<\/?p>/g, ''),
                  desc: alert.desc.concat('\n\nSolution:\n', alert.solution).replace(/<\/?p>/g, ''),
                  instanceDesc: instanceDescription
                });
              }
            }
          }
        } catch (error) {
          console.error('Error parsing Zap output:', error);
          process.exit(2);
        }
      }
      console.log(vulnerabilities);
      return vulnerabilities;
    }

    async function createZapJiraTicket(vulnerability) {
      try {
        const jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.name}" AND created >= startOfDay("-60d") AND status != "Canceled"`;
        const searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        
        const searchResult = searchResponse.data;
        if (searchResponse.status === 200) {
          if (!searchResult.issues || searchResult.issues.length === 0) {
            
            const username = core.getInput('assign-jira-ticket-to');
            const assignee_exist = await doesUserExist(username).catch(() => null);
            const assignee_key = `${core.getInput('is_jira_enterprise') === 'true' ? "name" : "accountId"}`;
            const assignee = { [assignee_key]: `${assignee_exist ? username : null}`}

            const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
            const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;
  
            const issue = {
              "fields": {
                "project": {
                  "key":  `${core.getInput('jira-project-key')}`
                },
                "summary": `${core.getInput('jira-title-prefix').concat(' ', vulnerability.name)}`,
                "description": `${vulnerability.desc.concat('\n', vulnerability.instanceDesc)}`,
                "issuetype": {
                  "name": `${core.getInput('jira-issue-type')}`
                },
                "assignee": assignee,
                "labels": core.getInput('jira-labels').split(','),
                ...(customJiraFields && Object.keys(customJiraFields).length > 0 && { ...customJiraFields }),
              }
            };
    
            const createIssueUrl = `/rest/api/2/issue`;
            const issueResponse = await jira.post(createIssueUrl, issue,);
    
            if (issueResponse.status === 201) {
              
              console.log(`Jira ticket created for vulnerability: ${vulnerability.name}`);
              return issueResponse.data;
            } else {
              console.error(`Error creating Jira ticket. Unexpected response status: ${issueResponse.status} ${issueResponse.statusText}`);
              process.exit(3);
            }
          } else {
            console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.name}`);
          }
        } else {
          console.error(`Error querying Jira. Unexpected response status: ${searchResponse.status} ${searchResponse.statusText}`);
          process.exit(3);
        }
      } catch (error) {
        console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
        process.exit(3);
      }
    }

    (async () => {
      const scanOutputFilePath = core.getInput('scan-output-path');
      const jsonData = fs.readFileSync(scanOutputFilePath, 'utf-8');

      const vulnerabilities = parseZapOutput(jsonData);
      console.log(`Parsed vulnerabilities: ${vulnerabilities.length}`);

      const uniqueVulnerabilities = Array.from(new Set(vulnerabilities.map(v => v.name)))
        .map(name => {
          return vulnerabilities.find(v => v.name === name);
        });

      for (const vulnerability of uniqueVulnerabilities) {
        try {
          console.log(`Creating Jira ticket for vulnerability: ${vulnerability.name}`);
          const resp = await createZapJiraTicket(vulnerability);
          console.log(resp);
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
          process.exit(3);
        }
      }
    })();
  } else if (scanType === 'snyk') {
    let snykTestType = ''
    const isMajorVersion = (v1, v2) => {
      if (!v1 || !v2 || typeof v1 !== 'string' || typeof v2 !== 'string' ||
          !/\d+\.\d+\.\d+/.test(v1) || !/\d+\.\d+\.\d+/.test(v2)) {
          return false; // If either version is not provided, or they are not in the correct format
      }
  
      const m = v1.split('.')[0]; // v1 is 1.0.4 -> 1
      const m2 = v2.split('.')[0]; // v2 is 2.4.5 -> 2
  
      return m2 - m > 0; // return true if v2's major version is greater than v1's major version
    }  
    function parseSnykOutput(inputData) {
      
      // severity level enum
      const Severities = {
        low: 1,
        medium: 2,
        high: 3,
        critical: 4
      };

      let vulnerabilities = [];
      const minSeverity = core.getInput('min-severity');
      if (minSeverity && !Severities[minSeverity]) {
        console.error("invalid input for min-severity; must be set to 'low', 'medium', 'high', or 'critical'");
        process.exit(2);
      }
      if (inputData) {
        const data = JSON.parse(inputData);
        if (Array.isArray(data)) {
          if (data.some(d => d.infrastructureAsCodeIssues)) {
            snykTestType = 'iac';
          } else if (data.some(d => d.vulnerabilities)) {
            snykTestType = 'open-source';
          }
        } else if (data && data.vulnerabilities) {
          snykTestType = 'container';
        }

        if (!snykTestType) {
          console.error('Error: Unable to determine Snyk scan type. Invalid or unknown data structure.');
          process.exit(1);
        }

        if (snykTestType === 'open-source') {
          try {
            
            if (Array.isArray(data)) {
              for (const project of data) {
                if (project && project.vulnerabilities && Array.isArray(project.vulnerabilities)) {                  
                  // vulnerabilities = vulnerabilities.concat(project.vulnerabilities);
                  project.vulnerabilities.forEach(v => {
                    if (minSeverity && Severities[v.severity] >= Severities[minSeverity]) {
                      vulnerabilities.push(v);
                    }
                  });
                } else {
                  console.error(`Error: Invalid project structure in open-source data. Project data: ${JSON.stringify(project)}`);
                }
              }
            }  else {
              console.error('Error: Open-source scan expected an array, but received invalid data.');
            }
          } catch (error) {
            console.error('Error parsing Snyk output:', error);
            process.exit(2);
            // vulnerabilities = parseNonJsonData(inputData);
          }
        }
        else if (snykTestType === 'container') {
          try {
            if (data && data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
              data.vulnerabilities.forEach(v => {
                if (minSeverity && Severities[v.severity] >= Severities[minSeverity]) {
                  vulnerabilities.push(v);
                }
              });
              // if more than one image is being scanned, any vulnerabilities found in any image after the first will be placed
              // in a `applications` array in the json output (not sure why it's done this way)
              if (data.applications && Array.isArray(data.applications)) {
                data.applications.forEach(app => {
                  if (app.vulnerabilities && Array.isArray(app.vulnerabilities)) {
                    app.vulnerabilities.forEach(v => {
                      if (minSeverity && Severities[v.severity] >= Severities[minSeverity]) {
                        vulnerabilities.push(v);
                      }
                    })
                  } else {
                    console.error(`Error: Invalid application structure in container scan. Application data: ${JSON.stringify(app)}`);
                  }
                });
              }
            } else {
              console.error('Error: Container scan expected "vulnerabilities" to be an array, but received invalid data.');
            }
          } catch (error) {
            console.error('Error parsing Snyk output:', error);
            process.exit(2);
            // vulnerabilities = parseNonJsonData(inputData);
          }
        }
        else if (snykTestType === 'iac') {
          try {
            if (data && Array.isArray(data)) {
              data.forEach(d => {
                if (Array.isArray(d.infrastructureAsCodeIssues) && d.infrastructureAsCodeIssues.length > 0) {
                  d.infrastructureAsCodeIssues.forEach(issue => {
                    if (minSeverity && Severities[issue.severity] >= Severities[minSeverity]) {
                      const iacIssue = { ...issue };
                      iacIssue.filePath = d.targetFilePath;
                      vulnerabilities.push(iacIssue);
                    }
                  });
                }  else {
                  console.error(`Error: Invalid IAC data structure. InfrastructureAsCodeIssues not found in data: ${JSON.stringify(d)}`);
                }
              });
            } else {
              console.error('Error: IAC scan expected an array, but received invalid data.');
            }
          } catch (error) {
            console.error('Error parsing Snyk output:', error);
            process.exit(2);
          }
        }  else {
          console.error(`Error: Unknown Snyk scan type "${snykTestType}".`);
        }

        if (vulnerabilities.length === 0) {
          console.error('No Vulnerabilities Detected');
        }

        return vulnerabilities;

      } else {
        console.error('No input-data/vulnerabilities Detected');
        // vulnerabilities = parseNonJsonData(inputData);
      }
    }

    function iacDescriptionStr(vulnerability) {
      let descriptionStr = "";
      descriptionStr += vulnerability.iacDescription.issue   ? `*Issue:*\n ${vulnerability.iacDescription.issue} \n\n ` : '';
      descriptionStr += vulnerability.iacDescription.impact  ? `*Impact:*\n ${vulnerability.iacDescription.impact} \n\n ` : '';
      descriptionStr += vulnerability.iacDescription.resolve ? `*Resolve:*\n ${vulnerability.iacDescription.resolve} \n\n` : '';
      descriptionStr += vulnerability.filePath               ? `*File:* ${vulnerability.filePath} \n\n ` : '';
      descriptionStr += vulnerability.lineNumber             ? `*Line Number:* ${vulnerability.lineNumber} \n\n` : '';
      descriptionStr += vulnerability.documentation          ? `*Documentation:* ${vulnerability.documentation}` : '';
      
      return descriptionStr;
    }

    async function createSnykJiraTicket(vulnerability, comment='', snykTestType = 'container') {
      try {
 
        const title = vulnerability.title.replaceAll("\"", "\\\"");
        const jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.title}" AND created >= startOfDay("-60d") AND status != "Canceled"`;
        const searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        
        const searchResult = searchResponse.data; 
        if (searchResponse.status === 200) {
          if (!searchResult.issues || searchResult.issues.length === 0) {
            
            const username = core.getInput('assign-jira-ticket-to');
            const assignee_exist = await doesUserExist(username).catch(() => null);
            const assignee_key = `${core.getInput('is_jira_enterprise') === 'true' ? "name" : "accountId"}`;
            const assignee = { [assignee_key]: `${assignee_exist ? username : null}`}

            const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
            const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;
            const issue = {
              "fields": {
                "project": {
                  "key": `${core.getInput('jira-project-key')}`
                },
                "summary": `${core.getInput('jira-title-prefix')}  ${vulnerability.title}`,
                "description": `${comment}${ snykTestType === 'iac' ? iacDescriptionStr(vulnerability) : vulnerability.description}`,
                "issuetype": {
                  "name": `${core.getInput('jira-issue-type')}`
                },
                "assignee": assignee,
                "labels": core.getInput('jira-labels').split(','),
                ...(customJiraFields && Object.keys(customJiraFields).length > 0 && { ...customJiraFields }),
              }
            };
    
            const createIssueUrl = `/rest/api/2/issue`;
            const issueResponse = await jira.post(createIssueUrl, issue);
    
            if (issueResponse.status === 201) {
              
              console.log(`Jira ticket created for vulnerability: ${vulnerability.title}`);
              return issueResponse.data;
            } else {
              console.error(`Error creating Jira ticket. Unexpected response status: ${issueResponse.status} ${issueResponse.statusText}`);
              process.exit(3);
            }
          } else {
            console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.title}`);
          }
        } else {
          console.error(`Error querying Jira. Unexpected response status: ${searchResponse.status} ${searchResponse.statusText}`);
          process.exit(3);
        }
      } catch (error) {
        console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
        process.exit(3);
      }
    }
    async function commentOnIssue(issueKey, commentText) {
      const createCommentUrl = `/rest/api/2/issue/${issueKey}/comment`; // Replace issueKey with the key of the issue you want to comment on
      const comment = {
          body: commentText // Replace "Your comment here" with the actual comment you want to post
      };

      const commentResponse = await jira.post(createCommentUrl, comment);
      return commentResponse;
    }
    (async () => {
      const scanOutputFilePath = core.getInput('scan-output-path');
      const majorVersionOnly = core.getInput('major-version-only');

      const jsonData = fs.readFileSync(scanOutputFilePath, 'utf-8');

      const vulnerabilities = parseSnykOutput(jsonData);
      console.log(`Parsed vulnerabilities: ${vulnerabilities.length}`);

      const uniqueVulnerabilities = Array.from(new Set(vulnerabilities.map(v => v.title)))
        .map(title => {
          return vulnerabilities.find(v => v.title === title);
        });
      if(majorVersionOnly == 'true') {
        for (const vulnerability of uniqueVulnerabilities) {
          try {
            const fixedIn = vulnerability.fixedIn? vulnerability.fixedIn.sort().reverse(): [];
            console.log(
              `Current Version is : ${vulnerability.version} and New Version recommendations : ${fixedIn}`
            );
            if(fixedIn.length && isMajorVersion(vulnerability.version, fixedIn[0])){
              const comment = `For this vulnerability, current version is : ${vulnerability.version} and new version recommendations : ${fixedIn}`;
              console.log('This version update is major update')
              console.log(
                  `Creating Jira ticket for vulnerability: ${vulnerability.title}`
              );
              const resp = await createSnykJiraTicket(vulnerability, comment, snykTestType);
              console.log(resp)
            } else {
              console.log('skipping because not major update')
            }
          } catch (error) {
            console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
            process.exit(3);
          }
        }
      } else {
        for (const vulnerability of uniqueVulnerabilities) {
          try {
              console.log(
                  `Creating Jira ticket for vulnerability: ${vulnerability.title}`
              );
              const resp = await createSnykJiraTicket(vulnerability);
              console.log(resp)
          } catch (error) {
            console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
            process.exit(3);
          }
        }
      }
    })();
  } else {
    console.error('Invalid scan-type provided. Please provide either "snyk" or "zap".');
    core.setFailed('Invalid scan-type provided');
    process.exit(4);
  }
} catch (error) {
  core.setFailed(error.message);
  process.exit(5);
}
