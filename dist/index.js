/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 320:
/***/ ((module) => {

module.exports = eval("require")("@actions/core");


/***/ }),

/***/ 383:
/***/ ((module) => {

module.exports = eval("require")("axios");


/***/ }),

/***/ 81:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 147:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 17:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
const fs = __nccwpck_require__(147);
const axios = (__nccwpck_require__(383)["default"]); 
const core = __nccwpck_require__(320);
const path = __nccwpck_require__(17);

// Install jira-client
core.startGroup('Installing jira-client');
const installJiraClient = (__nccwpck_require__(81).spawnSync)('npm', ['install', 'jira-client'], { stdio: 'inherit' });
core.endGroup();

// Install axios
core.startGroup('Installing axios');
const installAxios = (__nccwpck_require__(81).spawnSync)('npm', ['install', 'axios'], { stdio: 'inherit' });
core.endGroup();

// Install @actions/core
core.startGroup('Installing @actions/core');
const installActionsCore = (__nccwpck_require__(81).spawnSync)('npm', ['install', '@actions/core'], { stdio: 'inherit' });
core.endGroup();

// Install path
core.startGroup('Installing path module');
const pathInstall = (__nccwpck_require__(81).spawnSync)('npm', ['install', 'path'], { stdio: 'inherit' });
core.endGroup();

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
          process.exit(2);
          // vulnerabilities = parseNonJsonData(inputData);
        }
      }
      return vulnerabilities;
    }

    async function createSnykJiraTicket(vulnerability) {
      try {
 
        const title = vulnerability.title.replaceAll("\"", "\\\"");
        const jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.title}" AND created >= startOfDay("-60d") AND status != "Canceled"`;
        const searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
        
        console.log('Jira Search Response:', searchResponse.status, searchResponse.data);


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
          const resp = await createSnykJiraTicket(vulnerability);
          console.log(resp)
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
          process.exit(3);
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
})();

module.exports = __webpack_exports__;
/******/ })()
;