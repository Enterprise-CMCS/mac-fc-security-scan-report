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

// const token = core.getInput('jira-token');
// const jira_enterprise = axios.create({
//   baseURL: `https://${core.getInput('jira-host')}`,
//   headers: {
//     Authorization: `Bearer ${token}`,
//     'Content-Type': 'application/json',
//     // 'X-Atlassian-Token': 'no-check',
//   },
// });
// const jira = axios.create({
//     baseURL: `https://${core.getInput('jira-host')}`,
//     auth: {
//       username: core.getInput('jira-username'),
//       password: core.getInput('jira-token'),
//     },
//     headers: {
//       'Content-Type': 'application/json',
//       // 'X-Atlassian-Token': 'no-check',
//     },
//   });

const token = core.getInput('jira-token');
const baseURL = `https://${core.getInput('jira-host')}`;
const headers = {
  'Content-Type': 'application/json',
};

let jira;
const isJiraEnterprise = core.getInput('is_jira_enterprise') === 'true';

if (isJiraEnterprise) {
  jira = axios.create({
    baseURL,
    headers: {
      ...headers,
      Authorization: `Bearer ${token}`,
    },
  });
} else {
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
}


// Function to check if the user exists using the Jira REST API
async function doesUserExist(username) {
  try { 
    // const response = core.getInput('is_jira_enterprise') ? await jira_enterprise.get(`/rest/api/2/user?username=${username}`) : await jira.get(`/rest/api/2/user?accountId=${username}`);
    const response = await jira.get(`/rest/api/2/user?accountId=${username}`);
    if (response.status === 200) {
      // User exists (status code 200 OK)
      console.log('username:', core.getInput('jira-username'));
      console.log('host:', core.getInput('jira-host'));
      console.log('^^^^User found^^^^^^:', response.data);
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
        }
      }
      console.log(vulnerabilities);
      return vulnerabilities;
    }

    async function createJiraTicket(vulnerability) {
      try {
        const jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.name}" AND created >= startOfDay("60d") AND status != "Canceled"`;
        // const searchResponse = core.getInput('is_jira_enterprise') ? await jira_enterprise.get('/rest/api/2/search', { params: { jql: jqlQuery } }) : await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        const searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        const searchResult = searchResponse.data;
        if (searchResponse.status === 200) {
          if (!searchResult.issues || searchResult.issues.length === 0) {
            
            const username = core.getInput('assign-jira-ticket-to');
            const assignee_exist = await doesUserExist(username).catch(() => null);
            const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
            const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;
            const assignee_key = core.getInput('is_jira_enterprise') ? "name" : "accountId";
            const assignee = { [assignee_key]: `${assignee_exist ? username : null}`}
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
            const issueResponse = await jira.post(createIssueUrl, issue);
    
            if (issueResponse.status === 201) {
              
              console.log(`Jira ticket created for vulnerability: ${vulnerability.name}`);
              return issueResponse.data;
            } else {
              console.error(`Error creating Jira ticket. Unexpected response status: ${issueResponse.status} ${issueResponse.statusText}`);
              return null;
            }
          } else {
            console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.name}`);
          }
        } else {
          console.error(`Error querying Jira. Unexpected response status: ${searchResponse.status} ${searchResponse.statusText}`);
          return null;
        }
      } catch (error) {
        console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
        return null;
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
          const resp = await createJiraTicket(vulnerability);
          console.log(resp);
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
        }
      }
    })();
  } else if (scanType === 'snyk') {
    function parseSnykOutput(inputData) {
      let vulnerabilities = [];
      if (inputData) {
        try {
          const data = JSON.parse(inputData);
          if (Array.isArray(data)) {
            for (const project of data) {
              if (project && project.vulnerabilities && Array.isArray(project.vulnerabilities)) {
                vulnerabilities = vulnerabilities.concat(project.vulnerabilities);
              }
            }
          } else {
            console.error('No Vulnerabilities Detetcted or Invalid JSON data format.');
            // vulnerabilities = parseNonJsonData(inputData);
          }
        } catch (error) {
          console.error('Error parsing Snyk output:', error);
          // vulnerabilities = parseNonJsonData(inputData);
        }
      }
      return vulnerabilities;
    }

    async function createJiraTicket(vulnerability) {
      try {
 
        const title = vulnerability.title.replaceAll("\"", "\\\"");
        const jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.title}" AND created >= startOfDay("-60d") AND status != "Canceled"`;
        const searchResponse = core.getInput('is_jira_enterprise') ? await jira_enterprise.get('/rest/api/2/search', { params: { jql: jqlQuery } }) : await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        
        const searchResult = searchResponse.data; 
        if (searchResponse.status === 200) {
          if (!searchResult.issues || searchResult.issues.length === 0) {
            
            const username = core.getInput('assign-jira-ticket-to');
            const assignee_exist = await doesUserExist(username).catch(() => null);
            const assignee_key = core.getInput('is_jira_enterprise') ? "name" : "accountId";
            const assignee = { [assignee_key]: `${assignee_exist ? username : null}`}

            const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
            const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;
            
  
            const issue = {
              "fields": {
                "project": {
                  "key": `${core.getInput('jira-project-key')}`
                },
                "summary": `${core.getInput('jira-title-prefix')}  ${vulnerability.title}`,
                "description": `${vulnerability.description}`,
                "issuetype": {
                  "name": `${core.getInput('jira-issue-type')}`
                },
                "assignee": assignee,
                "labels": core.getInput('jira-labels').split(','),
                ...(customJiraFields && Object.keys(customJiraFields).length > 0 && { ...customJiraFields }),
              }
            };
    
            const createIssueUrl = `/rest/api/2/issue`;
            const issueResponse = core.getInput('is_jira_enterprise') ? await jira_enterprise.post(createIssueUrl, issue) : await jira.post(createIssueUrl, issue);
    
            if (issueResponse.status === 201) {
              console.log(`Jira ticket created for vulnerability: ${vulnerability.name}`);
              return issueResponse.data;
            } else {
              console.error(`Error creating Jira ticket. Unexpected response status: ${issueResponse.status} ${issueResponse.statusText}`);
              return null;
            }
          } else {
            console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.name}`);
          }
        } else {
          console.error(`Error querying Jira. Unexpected response status: ${searchResponse.status} ${searchResponse.statusText}`);
          return null;
        }
      } catch (error) {
        console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
        return null;
      }
    }

    (async () => {
      const scanOutputFilePath = core.getInput('scan-output-path');
      const jsonData = fs.readFileSync(scanOutputFilePath, 'utf-8');

      const vulnerabilities = parseSnykOutput(jsonData);
      console.log(`Parsed vulnerabilities: ${vulnerabilities.length}`);

      const uniqueVulnerabilities = Array.from(new Set(vulnerabilities.map(v => v.title)))
        .map(title => {
          return vulnerabilities.find(v => v.title === title);
        });

      for (const vulnerability of uniqueVulnerabilities) {
        try {
          console.log(`Creating Jira ticket for vulnerability: ${vulnerability.title}`);
          const resp = await createJiraTicket(vulnerability);
          console.log(resp)
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
        }
      }

    })();
  } else {
    console.error('Invalid scan-type provided. Please provide either "snyk" or "zap".');
    core.setFailed('Invalid scan-type provided');
  }
} catch (error) {
  core.setFailed(error.message);
}