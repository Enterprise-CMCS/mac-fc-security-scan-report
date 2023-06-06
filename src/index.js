const fs = require('fs');
const JiraClient = require('jira-client');
const core = require('@actions/core');
const github = require('@actions/github');

try {
   const jira = new JiraClient({
   protocol: 'https',
   host: process.env.JIRA_BASE_URL,
   username: process.env.JIRA_USER_EMAIL,
   password: process.env.JIRA_API_TOKEN,
   apiVersion: '2',
   strictSSL: true,
   });
   
   // Parse the json file from Zap scan 
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
             if (alert.riskcode === process.env.ZAP_RISK_CODE ) {
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
   
   // JQL query with relative date math, 
   //let jqlQuery = `project = "${process.env.JIRA_PROJECT_KEY}" AND summary ~ "${process.env.JIRA_TITLE_PREFIX}  ${title}" AND created >= startOfDay("-60d") AND status NOT IN ("Closed", "Cancelled")`;
   let jqlQuery = `project = "${process.env.JIRA_PROJECT_KEY}" AND summary ~ "MCR - SNYK ${vulnerability.name}" AND created >= startOfDay("-60d") AND status NOT IN ("Closed")`;
   
   let searchResult = await jira.searchJira(jqlQuery);
   
   if (!searchResult.issues || searchResult.issues.length === 0) {
     const issue = {
       fields: {
         project: {
           key: process.env.JIRA_PROJECT_KEY,
         },
         summary: process.env.JIRA_TITLE_PREFIX.concat(' ', vulnerability.name),
         description: vulnerability.desc.concat('\n', vulnerability.instanceDesc),
         issuetype: {
           name: process.env.JIRA_ISSUE_TYPE,
         },
         labels: process.env.JIRA_LABELS.split(','),
         // "customfield_10007" : process.env.JIRA_EPIC_KEY,
       },
     };
   
     
     const issueResponse = await jira.addNewIssue(issue);
     console.log(`Jira ticket created for vulnerability: ${vulnerability.name}`);
     
     const scanOutputFilePath = process.env.SCAN_OUTPUT_FILE_PATH;
   
     try {
       // Use the addAttachmentOnIssue method from the Jira library
       await jira.addAttachmentOnIssue(issueResponse.key, fs.createReadStream(scanOutputFilePath));
       console.log(`Jira ticket ${issueResponse.key} created successfully.`);
     } catch (error) {
       console.error(`Error adding attachment to Jira ticket ${issueResponse.key}:`, error);
     }
   
     return issueResponse;
   } else {
     console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.name}`);
   }
   }
   
   (async () => {
    //  const consoleOutputFile = process.argv[2];
     const scanOutputFilePath = process.env.SCAN_OUTPUT_FILE_PATH;
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
         console.log(resp)
       } catch (error) {
         console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
       }
     }
   
   })();
  } catch (error) {
    core.setFailed(error.message);
  }