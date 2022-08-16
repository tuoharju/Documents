# Flo Apps Security Policy

All data handled by Flo Apps Ltd is managed in accordance with the General Data Protection Regulation (GDPR; EU 2016/679).

We use data to provide services to our clients and to maintain our Customer Relationship Management (CRM). Flo Apps will keep client data as long as is required to fulfil these purposes, or as long as Flo Apps is obliged to do so in accordance with prevailing legislation.

Data that is shared with a third party will only be used in accordance with the purposes set forth in this Security Policy.

Should Flo Apps be subject to reorganisation, merger or sale, Flo Apps may transmit personal data to the relative third party, provided that such third party undertakes to handle the personal data in accordance with this Privacy Policy.

Flo Apps has taken technical and organisational measures to protect data from loss, manipulation or unauthorised access. Flo Apps adapts its security measures in accordance with progress and development of the relevant technical area.

## General Data Protection Regulation (GDPR)

The General Data Protection Regulation (http://www.eugdpr.org) protects rights of EU citizens. We regularly review and update our agreements, internal processes, procedures, data systems, and documentation to ensure we are in compliance with the GDPR regulations.

Under the GDPR regulations, customers have extended rights on how services manage their data, such as the right to rectification, access, and portability of the data as well as the right to be forgotten.

# Data in CRM, project management, and emailing lists

We store clients' basic contact details in our custom-made Customer Relationship Management (CRM) which runs on UpCloud London.

We are using FrontApp, based in the United States, to handle some of the email traffic and client communication. FrontApp has completed the EU-U.S. Privacy Shield certifications and we have signed an EU Data Processing Addendum with them. See https://community.frontapp.com/t/x1p4mw/is-front-compliant-with-gdpr for more information.

For project management, we use [Freedcamp](https://freedcamp.com), based in the United States.

To maintain email lists of our current and past clients, as well as potential future clients, we use MailChimp whose servers may be located outside the EEA. MailChimp has certified to the EU-U.S. Privacy Shield Framework and we have signed a Customer EU Data Processing Addendum with them. See https://kb.mailchimp.com/accounts/management/about-the-general-data-protection-regulation

# Security-related data

Our systems save such security-related data as logins and IP addresses. This data is deleted programmatically after a delay.

# Clients' data

Data owned by clients is stored exclusively within the European Economic Area (EEA) with these exceptions:

* during email transmissions, recipients' email addresses and email content may be handled outside the EEA
* during SMS transmissions, recipients' phone numbers and SMS content are handled outside the EEA
* backups for Edge server are kept on Dropbox whose data centers are in the United States

By using FloMembers membership management, FloRoyalties royalty management and / or bespoke database systems to keep personal data, client agrees that Flo Apps Ltd may manage client's data over the course of the agreement and beyond, until the end of the backups' life cycle.

While clients make the final decisions about the data they collect, data saved in database systems provided by Flo Apps typically include

1. such personal data as persons' names and addresses
1. such categories as "members" and "subscribers"

## Data procedures

Data is handled as follows:

### When client transfers data to us

When we get data from a new client, that data is saved in:

 * HESK support system on `Linode Frankfurt` (cron removes the data after a timeout)
 * personal computers (crons should be used to clean Downloads etc)
 * encrypted TimeMachine backups
 * production server (cron cleans backups)
 * offsite backups (and, in the case of `edge` server, mirrored back to Dropbox + TimeMachine)

Client data may also be present in

 * personal emails (in case a client sends data by email **against** guidelines; it is every employee's duty that these attachments be deleted)
 * printouts (these must be deleted promptly)

### Live data and offsite backups

Flo Apps Ltd uses servers hosted by following service providers.

 * DigitalOcean (Amsterdam, NL; Frankfurt, DE)
   * see https://www.digitalocean.com/security/
   * offsite FloMembers backups are kept on Dropbox (see https://www.dropbox.com/help/security/general-data-protection-regulation) and mirrored back to Flo Apps DPO's computer
   * offsite WordPress backups are kept on [ManageWP](https://managewp.com/) and on Dropbox

 * Linode (Frankfurt, DE; London, UK)
   * see https://www.linode.com/compliance
   * offsite WordPress backups are kept on [ManageWP](https://managewp.com/) and on Dropbox

 * Shellit.org (Ulvila, FI)
   * see https://tavu.io/en/features
   * offsite FloMembers backups are kept on UpCloud Helsinki

 * UpCloud (Helsinki, FI)
   * see https://www.upcloud.com/documentation/faq/
   * FI-HEL2 is located at Telia Helsinki Data Center with ISO 27001 certification for security standards
   * offsite FloMembers backups are kept on UpCloud Helsinki

### FloMembers backups

Each live FloMembers server creates nightly backups of the data. These backups are also copied to an offsite server, in order to provide redundancy.

We keep daily, weekly and monthly backups on each live server. Restoring from backups is tested frequently.

### Closing an installation

If a FloMembers installation is closed, remaining backups are removed gradually over a period of 12 months. In the event client wants to transfer their data from one system to another, data can be downloaded in MS Excel format. In some services this may require Flo Apps' assistance.
 
## Server Level Security

We protect servers in following ways:

 1. Operating systems and server software are updated regularly. 
 1. We periodically run automated software to scan server security.
 1. Server-wide firewalls are in place to regulate network traffic.
 1. Logs are kept for an extended period of time.
 1. We are using [Lynis](https://cisofy.com/lynis/) for server hardening.
 1. We are using Apache's `mod_security` module (web application firewall) on Edge server.
 1. We are using Apache's `mod_evasive` module (application layer module) on Edge server to protect against DoS attacks.
 1. Servers are overwritten before shutting them down when we migrate to new servers.

Services that are running on servers can be listed (`systemctl list-units --type service`) to make sure only necessary ones are running.

### Databases

Databases can not be accessed externally and only SSH key login is allowed.

On Ubuntu servers, MySQL security is enforced using `sudo mysql_secure_installation`. It can also be used to change `root` password for MySQL installation.

### Public Key Infrastructure

We use SSH keys to login to servers. Password login to servers is blocked.

SSH keys are also used in communication between GitHub repositories and the installations.

## Application Level Security (Generic)

### Client passwords

All passwords that system stores are saved using one-way hashing mechanisms. Flo Apps staff cannot view them. If a user loses their password, it cannot be retrieved — it must be reset.

### Logs

We keep a number of different logs on different levels. Some of these logs are cleaned automatically after a certain delay, some of them are kept permanently for security reasons. If a person has been removed permanently, their actions cannot be tracked down to the person after a certain delay. Anonymous data may still remain.

### SSL/TLS encryption

Backend applications' network traffic is encrypted with SSL.

## Application Level Security (FloMembers)

### Audit trail

Changes made to persons' data can be traced by user and date.

### Data downloads

Downloads are recorded in each installation and can be traced by user and date.

### Logins

All logins are written into a log. Login pages have brute force protection. System enforces medium password strength.

### Vulnerability scanners

We use two vulnerability scanners:

1. [Detectify](https://detectify.com/) runs automated vulnerability tests once a week.
1. [Intruder](https://www.intruder.io/) runs a full scan once a month and ad hoc tests whenever new threats emerge.

## Third-party integrations

When available, we use two-factor authentication to log into third party services.

### Bank transactions

Files that are fetched from banks are kept on our servers for 70 days (on `Core`, 180 days) and deleted via CRON operation.

### Facebook

FloMembers users can use their Facebook id's to log in.

### Google

#### Ads

For FloMembers Mini clients, we're using Google AdSense to show ads.

#### Analytics

We're using Google Analytics to

1. gather overall statistics of services' usage
1. to monitor and compare site loading times

#### Login

FloMembers users can use their Google credentials to log in.

### Mandrill

We use Mandrill (part of MailChimp) to deliver email. Full content of the messages is kept on Mandrill servers for 3 days, detailed information about sent messages for 30 days and bounced data for 90 days.

MailChimp Terms of Use and Privacy Policy cover how MailChimp manages and handles data and what commitments they make in terms of data. Additionally, the [MailChimp Security page](http://mailchimp.com/about/security) contains a lot of information relevant for both Mandrill and MailChimp.

MailChimp has certified to the EU-U.S. Privacy Shield Framework and we have signed a Customer EU Data Processing Addendum with them.

Mandrill's infrastructure is composed of three key components:

1) Relay servers, which accept mail from users through the API or SMTP integration
2) Application servers, which process and handle everything required for sending and storing data, and
3) Sending servers, which handle the actual delivery of emails to recipient servers

The relay servers (1) are located around the world in various Amazon-hosted regions to reduce latency. While these servers currently minimally process data to pass along to the application servers, they may in the future handle other functions as well. You can read more about these relay servers on [Mandrill blog](http://blog.mandrill.com/making-smtp-fast.html) and current locations are provided on [Mandrill status page](http://status.mandrillapp.com)

The application servers (2) are also currently hosted via Amazon and are located in the US-West region of the United States.

The delivery servers (3) are also located in the United States and are a combination of hosted servers and ones that are managed by Mandrill in a secure facility.

Amazon AWS Identity and Access Management is used for authentication to AWS-related resources. Data may be accessed from Mandrill offices, but is generally not stored there except when transiently stored on individual machines.

You can read more about security developments at Mandrill at http://blog.mandrill.com/security-at-mandrill.html

### Maventa

Invoice-related data is transferred to [Maventa](https://maventa.com/) when e-invoices are sent. Client can delete this data via Maventa panel.

### Paytrail

Our clients use [Paytrail](https://www.paytrail.com/) to handle online payments in FloMembers.

### Posti Group

Address data that is fetched from Posti is kept in a text file on our servers for approximately 3 months and deleted when the next address update batch is run.

### Postituspalvelu Navakka

We are using [Postituspalvelu Navakka](http://www.postituspalvelunavakka.fi/) to send letters by post. We have signed a Data Processing Agreement with them.

### Postmark

We have signed a Data Processing Addendum with Postmark. For more information on Postmark's EU Data Protection policy, see https://postmarkapp.com/eu-privacy

### SendinBlue

We are currently routing some 10 - 20 % of the email traffic via [SendinBlue](https://www.sendinblue.com/).

### Tawk

We use Tawk to provide support chat. Tawk keeps email addresses for those persons who are logged into FloMembers when using the chat. For more information, see https://www.tawk.to/data-protection/dpa-data-processing-addendum/

### Twilio

FloMembers uses Twilio to deliver SMS's. Flo Apps Ltd and Twilio Inc. have a signed agreement on EC Data Protection.

Twilio maintains a security white paper with details on their security methods https://s3.amazonaws.com/ahoy-assets.twilio.com/Whitepapers/Twilio_Whitepaper_Security-Architecture.pdf. Information on data handling can also be found in their [Terms of Service](https://www.twilio.com/legal/tos) and [Privacy Policy](https://www.twilio.com/legal/privacy).

Summarizing some points regarding data security:

- their physical infrastructure is secured with visitor management etc. 
- Twilio uses AWS data centers and therefore they rely upon the security of Amazon services.

In respect to backups, according to their white paper, "Twilio performs regular backups of Twilio account information, [...] and other critical data using Amazon S3 cloud storage. All backups are encrypted in transit and at rest using strong encryption. Backup files are stored redundantly across multiple availability zones and are encrypted."

Regarding data transfer, Twilio may transfer some data to the US; however, they are committed to complying with EU data protection requirements. Protection and safeguards are applied to any transfer. 

Information on Twilio's anti-fraud practices can be viewed here: https://www.twilio.com/docs/api/security/anti-fraud

### Twitter

FloMembers users can use their Twitter id's to log in.

## Procedure for Security Breaches

 1. Determine
     * functional impact (to what extent does the incident affect the ability to provide services to users?)
     * information impact (was information compromised in any way and to what extent?)
     * recoverability (what kind of resources are needed to recover from the incident?)
 1. Containment
     * if needed, shut down services to block any further unauthorised use
     * services can be shut down at employees' own discretion - better safe than sorry
 1. Make sure situation cannot escalate
 1. Block any security holes
 1. Reopen services
 1. Inform clients and / or authorities in an appropriate and prompt manner
 1. Consider the lessons that can be drawn
 1. Write a report
     * incident details (what happened and when, how the incident was prioritized, what action was taken)
     * relevant investigation results, e.g. the cause of the incident and its business impact

### Informing clients

Flo Apps shall document all security breaches and shall notify clients of all breaches without undue delay, but no later than two (2) business days after Flo Apps becomes aware of a security infringement. The notification shall include the following information:

 1. a description of the security breach including information about what registered groups and person registers have been affected by the security infringement and the estimated number of these groups and registers
 1. the name and contact details of Flo Apps contact person responsible for investigating the security breach
 1. a description of the actual consequences and / or likely consequences of a security breach
 1. a description of the actions Flo Apps has taken in response to a security breach and mitigating its adverse effects

If the above information is not possible to provide in a single message, information may be provided in parts.

## Future suggestions

 1. Check file modifications (specially critical ones like password, hosts, etc.)
 1. Isolated Execution Environments
 1. File Auditing and Intrusion Detection Systems (e.g. Tripwire, Aide)
 1. Run `OWASP ZAP` (see GitHub)

## Flo Apps Ltd premises

Flo Apps' office is restricted to authorized personnel and is monitored with cameras.

## Flo Apps Ltd employees

Flo Apps Ltd employees are committed to fulfilling data protection requirements imposed by both national and EU laws and maintaining a high level of confidentiality as regards any personal data. Employees are given regular briefings and training sessions on data protection issues.

In the unlikely event of security breaches by Flo Apps Ltd employees, persons can be subjected to

 1. verbal warnings
 1. written warnings
 1. termination of work agreement
 1. further sanctions imposed by law

Flo Apps is committed to employing sufficient human resources to maintain a high level of security.

## Subcontractors

Flo Apps Ltd may utilise subcontractors for e.g. developing new features. We do not share sensitive client data with the subcontractors.

## Data Protection Officer

Data Protection Officer for Flo Apps Ltd is Tapio Nurminen (CEO).

## Questions

You may contact us at any time for requests related to your expanded rights, we will be prepared to serve those requests:

 - Right to object: You may opt out of inclusion.
 - The right to be forgotten: in which case your data will be permanently deleted from our systems.
 - Right to ratification: we will update any information about you, which you wish to correct, amend or delete.
 - The right to access: we will describe the data we collect and how it is used.
 - The right to portability: we will provide an export of the data we have about you.
 
Flo Apps Ltd is also prepared to accept clients' audit requests as they may arise.

For information concerning Flo Apps's handling of personal data, please contact Flo Apps via email at feedback@floapps.com
