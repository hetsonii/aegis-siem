'use strict';
// Shared reference data for the console. The rule list mirrors the detection
// engine (lambdas/detection/detector.py) so the Detections page and ATT&CK
// coverage matrix stay in lock-step with what actually fires.
window.AEGIS = window.AEGIS || {};

AEGIS.SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
AEGIS.SEV_COLOR = {
  CRITICAL: '#f43f5e', HIGH: '#fb923c', MEDIUM: '#fbbf24',
  LOW: '#38bdf8', INFO: '#64748b',
};
AEGIS.SEV_ORDER = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

AEGIS.TACTICS = [
  'Reconnaissance', 'Initial Access', 'Execution',
  'Credential Access', 'Discovery', 'Defense Evasion', 'Impact',
];

AEGIS.RULES = [
  { id: 'sqli', name: 'SQL Injection', severity: 'HIGH', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'SQL metacharacters or boolean/union patterns in request input.' },
  { id: 'xss', name: 'Cross-Site Scripting', severity: 'MEDIUM', technique: 'T1059.007', technique_name: 'JavaScript', tactic: 'Execution', desc: 'HTML/JS injection patterns in request input.' },
  { id: 'command_injection', name: 'OS Command Injection', severity: 'CRITICAL', technique: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution', desc: 'Shell metacharacters chaining OS commands.' },
  { id: 'ssti', name: 'Server-Side Template Injection', severity: 'HIGH', technique: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution', desc: 'Template expression syntax such as {{7*7}} or ${...}.' },
  { id: 'log4shell', name: 'Log4Shell / JNDI Injection', severity: 'CRITICAL', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'JNDI lookup string (CVE-2021-44228 family).' },
  { id: 'nosqli', name: 'NoSQL Injection', severity: 'HIGH', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'MongoDB-style operators in input.' },
  { id: 'xxe', name: 'XML External Entity', severity: 'HIGH', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'External entity / DOCTYPE SYSTEM declaration.' },
  { id: 'path_traversal', name: 'Path Traversal', severity: 'HIGH', technique: 'T1083', technique_name: 'File and Directory Discovery', tactic: 'Discovery', desc: 'Directory traversal sequences.' },
  { id: 'lfi_rfi', name: 'File Inclusion (LFI/RFI)', severity: 'HIGH', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'PHP wrappers or remote include of a script.' },
  { id: 'ssrf', name: 'Server-Side Request Forgery', severity: 'HIGH', technique: 'T1552.005', technique_name: 'Cloud Instance Metadata API', tactic: 'Credential Access', desc: 'Requests coerced toward internal or cloud-metadata addresses.' },
  { id: 'open_redirect', name: 'Open Redirect', severity: 'LOW', technique: 'T1189', technique_name: 'Drive-by Compromise', tactic: 'Initial Access', desc: 'Redirect/next parameter pointing off-site.' },
  { id: 'sensitive_file', name: 'Sensitive File Access', severity: 'MEDIUM', technique: 'T1083', technique_name: 'File and Directory Discovery', tactic: 'Discovery', desc: 'Probing for secrets, VCS, backups, or config files.' },
  { id: 'scanner', name: 'Automated Scanner', severity: 'LOW', technique: 'T1595', technique_name: 'Active Scanning', tactic: 'Reconnaissance', desc: 'Known offensive-tool user agents.' },
  { id: 'pii_exposure', name: 'Sensitive Data in Request', severity: 'MEDIUM', technique: 'T1552', technique_name: 'Unsecured Credentials', tactic: 'Credential Access', desc: 'PII/secret patterns (email, card, key) present in input.' },
  { id: 'unauthorized_admin_access', name: 'Admin Access Attempt', severity: 'HIGH', technique: 'T1078', technique_name: 'Valid Accounts', tactic: 'Defense Evasion', desc: 'Direct request to an administrative surface.' },
  { id: 'idor_probe', name: 'Broken Access Control (IDOR)', severity: 'MEDIUM', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: "Object reference manipulated to reach another user's resource." },
  { id: 'recon_404', name: 'Recon / Enumeration', severity: 'LOW', technique: 'T1595', technique_name: 'Active Scanning', tactic: 'Reconnaissance', desc: 'Probing for non-existent paths (content discovery).' },
  { id: 'http_method_abuse', name: 'Dangerous HTTP Method', severity: 'LOW', technique: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', desc: 'Use of PUT/DELETE/TRACE against the app.' },
  { id: 'brute_force', name: 'Brute Force', severity: 'HIGH', technique: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', desc: 'Many failed logins from one source in a short window.', stat: true },
  { id: 'credential_stuffing', name: 'Credential Stuffing', severity: 'HIGH', technique: 'T1110.004', technique_name: 'Credential Stuffing', tactic: 'Credential Access', desc: 'Failed logins across many distinct usernames from one source.', stat: true },
  { id: 'rate_anomaly', name: 'Request-Rate Anomaly', severity: 'MEDIUM', technique: 'T1498', technique_name: 'Network Denial of Service', tactic: 'Impact', desc: 'Request rate from one source far above baseline.', stat: true },
  { id: 'blocked_request', name: 'Blocked Source Retry', severity: 'LOW', technique: 'T1498', technique_name: 'Network Denial of Service', tactic: 'Impact', desc: 'A blocked source is still sending requests.', stat: true },
  { id: 'new_source', name: 'New Source', severity: 'INFO', technique: null, technique_name: null, tactic: null, desc: 'First time this source has been observed.', stat: true },
];

AEGIS.RULE_BY_ID = Object.fromEntries(AEGIS.RULES.map((r) => [r.id, r]));

// techniques grouped by tactic, for the coverage matrix
AEGIS.techniquesByTactic = function () {
  const m = {};
  AEGIS.TACTICS.forEach((t) => { m[t] = {}; });
  AEGIS.RULES.forEach((r) => {
    if (r.tactic && r.technique) m[r.tactic][r.technique] = r.technique_name;
  });
  return m;
};
