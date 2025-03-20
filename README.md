![aws-banner](https://github.com/user-attachments/assets/727960bf-4184-4109-bfa6-3ab7c8d54c7a)


# AWS Security Best Practices Implementation Guide

A comprehensive, hands-on guide to securely configuring and hardening AWS environments. This guide covers step-by-step techniques, best practices, and practical testing methods to strengthen your cloud security posture in AWS.

---

## 🚀 **Overview**

This guide is designed for cybersecurity enthusiasts, students, security engineers, and IT professionals who wish to learn and apply security best practices within AWS. By following this guide, you will be able to:

- Secure your AWS account and IAM configurations.  
- Harden essential AWS services (IAM, EC2, S3).  
- Implement proactive monitoring and alerting with CloudTrail, CloudWatch, and more.  
- Simulate common cloud attack scenarios and understand how to protect against them.  

---

## 📖 Guide Outline

**[1. AWS Account Setup & IAM Security](#1-aws-account-setup--iam-security)**  
- [Creating an AWS Account (Root User Setup)](#creating-an-aws-account-root-user-setup)  
- [Creating IAM Users and Roles (Admin User & Role-Based Access)](#creating-iam-users-and-roles-admin-user--role-based-access)  
- [Implementing Least-Privilege IAM Policies](#implementing-least-privilege-iam-policies)  
- [IAM Activity Logging & Monitoring](#iam-activity-logging--monitoring)

**[2. Securing AWS Core Services](#2-securing-aws-core-services)**  
- [EC2 Security](#ec2-security)  
  - [Insecure EC2 Example](#insecure-ec2-example)  
  - [Configuring Security Groups (Virtual Firewalls)](#configuring-security-groups-virtual-firewalls)  
  - [SSH Key Management (EC2 Key Pairs)](#ssh-key-management-ec2-key-pairs)  
  - [Encrypting EBS Volumes at Rest](#encrypting-ebs-volumes-at-rest)  
- [S3 Security](#s3-security)  
  - [Blocking Public Access](#blocking-public-access)  
  - [Enforcing Encryption for S3 Objects](#enforcing-encryption-for-s3-objects)  
  - [S3 Logging & Auditing (Access Logs & Monitoring)](#s3-logging--auditing-access-logs--monitoring)

**[3. Logging & Monitoring with CloudTrail & CloudWatch](#3-logging--monitoring-with-cloudtrail--cloudwatch)**  
- [Enabling AWS CloudTrail (Account-Wide Logging)](#enabling-aws-cloudtrail-account-wide-logging)  
- [CloudWatch Alarms for Security Events](#cloudwatch-alarms-for-security-events)

**[4. Simulated Attack Scenarios & Fixes](#4-simulated-attack-scenarios--fixes)**  
- [Scenario 1: Misconfigured S3 Bucket (Public Data Leak)](#scenario-1-misconfigured-s3-bucket-public-data-leak)  
- [Scenario 2: Overly Permissive IAM Role (Privilege Escalation)](#scenario-2-overly-permissive-iam-role-privilege-escalation)  
- [Scenario 3: EC2 Instance with Open Ports (External Attack)](#scenario-3-ec2-instance-with-open-ports-external-attack)

**[5. Compliance & Best Practices Mapping](#5-compliance--best-practices-mapping)**  
- [Alignment with CIS AWS Foundations Benchmark](#alignment-with-cis-aws-foundations-benchmark)  
- [Meeting NIST SP 800-53 Controls](#meeting-nist-sp-800-53-controls)  
- [SOC 2 Trust Services Criteria](#soc-2-trust-services-criteria)  
- [Other Frameworks (GDPR, ISO 27001, PCI DSS)](#other-frameworks-gdpr-iso-27001-pci-dss)

---

## ✅ **Testing & Validation**

Throughout this guide, you will find practical test scenarios and verification steps to ensure every security measure is correctly implemented. Each section includes screenshots, command examples, and log validation methods to confirm your configurations are secure and effective.

---

## 🖼 **Screenshots & Illustrations**

Screenshots and diagrams throughout this guide are provided to illustrate each step clearly and are hosted directly on GitHub.

_Example:_

![Screenshot 2025-03-19 at 10 33 10 PM](https://github.com/user-attachments/assets/445548f3-b5d3-4efc-a8f1-8c68fc8c920d)


---

## 💡 **Cost Management**

While this guide is designed to minimize costs by using AWS Free Tier and short-lived resources, be aware that some AWS services might incur minor charges. Always check your AWS billing dashboard after testing, and ensure all test resources are terminated or cleaned up after use.

---


## ⚠️ **Disclaimer**

This guide is intended for educational purposes only. AWS regularly updates their console user interface (UI) and user experience (UX), which may result in certain features, resources, or configurations being relocated, renamed, or changed slightly. If something in the guide does not match exactly, consult the latest AWS documentation or console for up-to-date steps.

Always adhere to your organization's policies, guidelines, and AWS terms of service. The author is not responsible for any misuse, misconfiguration, or damages resulting from following this guide.

---

## 1. AWS Account Setup & IAM Security

### Creating an AWS Account (Root User Setup)

### **Disclaimer: Payment Method Required**

> **Note:** When creating a new AWS account, **a valid payment method** (such as a credit or debit card) is **required** to finalize the account setup. Although AWS provides a generous Free Tier, AWS will still place a temporary authorization charge (typically a few dollars) on your payment method to verify its validity. This temporary hold will disappear from your statement after your payment method is verified. Always monitor your usage to avoid unexpected charges.

---

To get started, navigate to the [**AWS home page**](https://aws.amazon.com) and click **Create an AWS account**. You will be guided through entering your email, account name, and contact details. Set a **strong root account password** (AWS enforces a mix of uppercase, lowercase, numbers, and symbols). After account creation, **secure the root user** immediately:

![Screenshot 2025-03-19 at 11 49 09 AM](https://github.com/user-attachments/assets/03c55c0d-7c23-4c43-997d-6bc810e6c998)

- **Enable MFA on the root account:**  
  Log in as root, go to **Security Credentials** by clicking your username in the top right menu, and click Security credential. On the under Security credentials page under “Multi-Factor Authentication (MFA)” choose to **assign a virtual MFA device**. You will be presented with 3 options; for this guide, we’ll use an Authenticator app. Input a device name, select Authenticator app, and hit next. Scan the QR code with your authenticator app and input the two consecutive one-time codes to activate MFA. Once done, click **Add MFA** and you will be redirected back to the IAM dashboard with a notification "MFA device assigned".

  ![Screenshot 2025-03-19 at 11 52 52 AM](https://github.com/user-attachments/assets/cceac70e-10ae-4a4f-8760-c8000d8a511b)  
  ![Screenshot 2025-03-19 at 11 57 11 AM](https://github.com/user-attachments/assets/3c086bfb-ad27-4bab-8ff8-9ebb1d42525c)  
  ![Screenshot 2025-03-19 at 12 02 44 PM](https://github.com/user-attachments/assets/1e6b66cd-dec4-403b-a86b-c0ac1ea96bda)  
  ![Screenshot 2025-03-19 at 12 05 58 PM](https://github.com/user-attachments/assets/4d0cfd1d-166e-4678-a6a3-2fa0a52dfc37)  
  ![Screenshot 2025-03-19 at 12 11 39 PM](https://github.com/user-attachments/assets/f0717935-a995-4b22-9b6c-69dae6f639ae)

> **IMPORTANT:** **Store root credentials securely.** The root user has unrestricted access to your AWS account. **Do not use the root account for daily tasks** or create access keys for it. AWS best practices recommend using root only for initial setup and for tasks that **require** root privileges (e.g., account-wide settings).

---

### Creating IAM Users and Roles (Admin User & Role-Based Access)

Rather than using the root user day-to-day, it’s recommended to manage user access through **IAM Identity Center** (formerly AWS SSO) for production environments. IAM Identity Center allows you to centrally manage AWS console access with features like multi-factor authentication and integration with external identity providers. For organizations managing many users or multiple AWS accounts, this approach simplifies user provisioning, de-provisioning, and access control.

However, for testing purposes or in scenarios where you need a dedicated IAM user, you can also create an IAM user directly. Below are both methods:

#### Option 1: Using IAM Identity Center (Best Practice)

1. **Set Up IAM Identity Center:**  
   - Navigate to the **IAM Identity Center** console.  
   - Follow the [IAM Identity Center documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html) to configure your identity source and add users.  
   - Assign permissions by creating permission sets that adhere to the principle of least privilege.  
   - This approach centralizes your user management and reduces the risk of credential sprawl.

2. **Assign Access:**  
   - Map users from your identity provider to AWS accounts using IAM Identity Center.  
   - Ensure that multi-factor authentication (MFA) is enforced for every user.

> **Note:** AWS recommends using IAM Identity Center for managing AWS console access instead of creating individual IAM users. This method not only improves security but also simplifies administration across multiple accounts.

#### Option 2: Creating an IAM User (For Testing/Specific Use Cases)

If you choose to create an IAM user directly, follow these steps:

1. **Create an Admin Group:**  
   - Go to the **IAM console**, select **User Groups**, and create a group (e.g., “Administrators”).  
   - Attach the managed policy **AdministratorAccess** to this group. This grants full access to AWS services for members of the group.  
   - You may choose your own group permission policies or create custom policies to adhere to your organization’s requirements.  
   - Once done, click **Create user group**.

   ![Screenshot 2025-03-19 at 12 16 44 PM](https://github.com/user-attachments/assets/1f2fa82f-aa3d-4ca8-a5e8-839721eea123)  
   ![Screenshot 2025-03-19 at 12 20 12 PM](https://github.com/user-attachments/assets/a54c8a73-b57d-4ac0-bf75-e0999b3324c3)  
   ![Screenshot 2025-03-19 at 12 58 45 PM](https://github.com/user-attachments/assets/0739cfab-193e-4d82-a6e0-efc400d0993d)  
   ![image](https://github.com/user-attachments/assets/1c84892b-ac88-4fdf-87e8-26808b0f783f)

2. **Create an IAM User:**  
   - In IAM, click **Users** → **Create user**.  
   - Provide a username (e.g., “AdminUser”) and enable **AWS Management Console access** with a custom password for interactive login.  
   - Consider checking **Require password reset** on first login.  
   - For permissions, add the user to the “Administrators” group you created.

   ![Screenshot 2025-03-19 at 1 03 32 PM](https://github.com/user-attachments/assets/a9bf6286-0eb9-47df-832e-ba935a4840f8)  
   ![Screenshot 2025-03-19 at 1 26 47 PM](https://github.com/user-attachments/assets/bb9da671-6fe6-4f95-b10e-ebd0b9eb7bef)  
   ![Screenshot 2025-03-19 at 1 28 29 PM](https://github.com/user-attachments/assets/c1a0e7f0-f59e-47d1-a354-739bcda64cb9)  
   ![Screenshot 2025-03-19 at 1 33 57 PM](https://github.com/user-attachments/assets/443cc9ef-212b-4daa-823b-eeac64b73f66)

   > **Important:** Although creating an IAM user is supported for testing, AWS best practices now favor using IAM Identity Center for console access. If possible, implement IAM Identity Center in production environments to improve security and simplify management.

3. **Enable MFA for the IAM User:**  
   - After creation, open the user’s Security Credentials tab and assign a virtual MFA (similar to root).  
   - This adds an extra layer of security for the IAM user login.

   ![Screenshot 2025-03-19 at 1 39 33 PM](https://github.com/user-attachments/assets/71ceec1f-3673-4208-8378-932400347a72)

   - After setting up MFA for your admin user, verify MFA is enabled:

     ![Screenshot 2025-03-19 at 1 50 58 PM](https://github.com/user-attachments/assets/2a6fd8ce-6458-4470-920b-55c6fc7d2491)

   > **Note:** Going forward, use this IAM user for administrative tasks. The root user (protected with MFA) should be used sparingly (for example, to configure account-level settings or in emergency scenarios).

---

IAM roles are used to delegate access within or between AWS services. For instance, you might create:  
- An **EC2 role** that grants instances permission to read from an S3 bucket (instead of embedding AWS keys on the instance).  
- A **Lambda execution role** that allows a function to write to a DynamoDB table.

Roles have no password; they rely on temporary credentials and can be assumed by trusted entities. Create roles by specifying the AWS service as the trusted principal and attaching an appropriate policy. This enables **role-based access control**.

### Implementing Least-Privilege IAM Policies

Adopt the principle of **least privilege** when assigning permissions. This means each user or role should have only the minimum permissions necessary to perform their tasks. Start by granting broad access when learning requirements, then refine over time:

- **Use AWS Managed Policies as a Baseline:** AWS provides many managed policies for common job functions. For example, use **ReadOnlyAccess** for auditors or **AmazonS3ReadOnlyAccess** for a role that only needs S3 read access.  
- **Create Customer-Managed Policies for Least Privilege:** Review CloudTrail logs or Access Advisor data to see which services and actions are being used, then craft a custom policy allowing only those actions.  
- **Use IAM Access Analyzer:** IAM Access Analyzer can **generate fine-grained policies** based on past activity, helping you identify permissions your IAM roles have never used.  
- **Regularly Review IAM Principals:** Remove unused IAM users or roles and rotate credentials regularly.  

By restricting IAM policies, you reduce the blast radius if a set of credentials is compromised. For example, an IAM role that only permits reading a specific S3 bucket cannot be misused to delete other buckets or access other services. In summary: **grant minimal required permissions and nothing more** ([Security best practices in IAM - AWS Identity and Access Management](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#:~:text=Apply%20least)).

### IAM Activity Logging & Monitoring

AWS IAM is tightly integrated with **AWS CloudTrail** for auditing. **CloudTrail** records all IAM API calls (e.g., user logins, policy changes, creation/deletion of users or roles). By default, CloudTrail will log IAM management events in each region.

To ensure comprehensive logging:

- **Enable a Trail:** In the CloudTrail console, create a **trail** to capture management events across _all_ regions. Choose an S3 bucket (with encryption) to store the logs.  
- **Turn on Log File Validation:** Enable **log file validation** when creating the trail to detect any tampering with the log files.  
- **Integrate with CloudWatch Logs:** Optionally, configure the trail to send logs to CloudWatch Logs for real-time monitoring and forensic analysis.

In addition to CloudTrail, consider enabling **AWS Config** rules to continuously evaluate IAM settings (e.g., checking whether MFA is enabled for IAM users or if an IAM policy is too broad). Together, CloudTrail (activity logging) and AWS Config (compliance checks) provide a robust solution for monitoring and detecting unauthorized changes in IAM.

Finally, regularly review IAM logs and set up alerts for anomalous behavior (see the next step-by-step setup). IAM is your first line of defense; monitoring its usage is critical to detecting credential misuse or privilege escalation.

---

### IAM Activity Logging & Monitoring Setup

Below is a **step-by-step guide** on how to set up and verify IAM activity logging and monitoring using AWS CloudTrail (and optionally AWS Config), along with suggestions on using CloudWatch Logs Insights to drill into IAM events.

---

#### 1. Log in to the AWS Console

- Sign in to the [AWS Management Console](https://aws.amazon.com/) if you're not already logged in.

---

#### 2.1. Navigate to AWS CloudTrail

- In the console’s search bar, type “CloudTrail” and select the CloudTrail service.

![Screenshot 2025-03-19 at 2 01 54 PM](https://github.com/user-attachments/assets/dcbcc42a-0b93-4a95-aa22-d5e2abb504ed)

---

#### 3. Create a New CloudTrail Trail

##### Step 3.1
- In the CloudTrail page, click **Create a trail**.

![Screenshot 2025-03-19 at 2 04 30 PM](https://github.com/user-attachments/assets/bc20ed06-b2f6-4a52-9e4a-fb238e4741ee)

##### Step 3.2  
- **Trail Name:** Enter a name (e.g., `MyCloudTrail`).

![Screenshot 2025-03-19 at 2 17 40 PM](https://github.com/user-attachments/assets/135572ce-f0a6-4872-9062-b74969499e9b)

##### Step 3.3  
- Under **Management events**, verify that both **Read/Write events** are enabled.  
- (Optional) Under **Data events**, select S3 or Lambda if you wish to capture object-level activity (this may incur extra costs).

![Screenshot 2025-03-19 at 2 23 39 PM](https://github.com/user-attachments/assets/64ff2290-a0eb-4ceb-9fb4-1283f8f277fb)  
![Screenshot 2025-03-19 at 2 28 20 PM](https://github.com/user-attachments/assets/4606bac1-c6f0-46ef-a6e6-9c6dcd46edd2)  
![Screenshot 2025-03-19 at 2 32 26 PM 1](https://github.com/user-attachments/assets/d8ad0f09-ab7e-44aa-b11a-fdaa6821d77b)

##### Step 3.4  
- **Storage Location:** Click **Edit** on the General details section of your newly created CloudTrail.  
  - Choose an existing bucket or create a new one.  
  - If creating a new bucket, follow the prompts, and ensure bucket encryption is enabled.

![Screenshot 2025-03-19 at 3 24 27 PM](https://github.com/user-attachments/assets/bfa6bd07-8b5b-49f7-b6b2-d5dda0a70177)

##### Step 3.5  
- **Log File Validation:** Check **Enable log file validation**. This ensures that any tampering with the logs can be detected using SHA-256 hashes.

![Screenshot 2025-03-19 at 3 29 03 PM](https://github.com/user-attachments/assets/f4596483-d4a5-4561-b1aa-1286d79de3c2)  
![Screenshot 2025-03-19 at 3 33 04 PM](https://github.com/user-attachments/assets/057b3806-819c-4d81-b759-c11d1d49dc80)

##### Step 3.6 (Optional)  
- **Integrate with CloudWatch Logs:**  
  - Scroll down to the CloudWatch Logs section and click **Edit**.  
  - Enter a Log Group name (e.g., `CloudTrail-Logs`). AWS will prompt you to create an IAM role granting CloudTrail permissions to write to CloudWatch Logs.

![Screenshot 2025-03-19 at 3 35 58 PM](https://github.com/user-attachments/assets/5ff54dc7-7a15-4efc-a4e8-de0ca7fd3634)  
![Screenshot 2025-03-19 at 3 39 08 PM](https://github.com/user-attachments/assets/50fffdbd-a6a3-42bc-890d-c839c3beb2e8)  
![Screenshot 2025-03-19 at 3 45 16 PM](https://github.com/user-attachments/assets/8b2b5a33-ee84-4f38-8ab3-eaab3ac210ac)

---

#### 5. Check CloudWatch Logs Integration

##### Step 5.1  
- Navigate to the [CloudWatch console](https://console.aws.amazon.com/cloudwatch/).

##### Step 5.2  
- Click on **Logs** in the sidebar and select the Log Group you configured (e.g., `CloudTrail-Logs`).

![Screenshot 2025-03-19 at 4 37 52 PM](https://github.com/user-attachments/assets/06e13039-9ebd-4fe4-aa44-97a19fc3dc64)

##### Step 5.3  
- Verify that log events are being received in that log group. You should see log streams (for example, 4 log streams in this screenshot).

![Screenshot 2025-03-19 at 4 43 19 PM](https://github.com/user-attachments/assets/803bea59-ef45-461e-a39d-85db873c9119)

##### Step 5.4: Use Logs Insights to Query IAM Data  
- Use a simple Logs Insights query to filter for IAM events from CloudTrail logs.

  **Example:**
  ```sql
  fields @timestamp, eventSource, eventName, userIdentity.arn, userIdentity.userName
  | filter eventSource = "iam.amazonaws.com"
  | sort @timestamp desc
  | limit 20
  ```

  ![Screenshot 2025-03-19 at 4 29 47 PM](https://github.com/user-attachments/assets/5d188e66-e0e9-4e8b-b6f6-47adb2762716)  
  ![Screenshot 2025-03-19 at 4 33 38 PM](https://github.com/user-attachments/assets/e76d5dc0-e492-4b5c-94c1-5ac8caabdf9d)

---

#### 6. (Optional) Enable AWS Config for IAM Resources

##### Step 6.1  
- In the search bar, search for **AWS Config** and select it.

![Screenshot 2025-03-19 at 4 56 45 PM](https://github.com/user-attachments/assets/a23198ae-0f96-4a4f-8911-20dcb9eba257)

##### Step 6.2  
- Click **Get started** (if you haven’t configured it before).

##### Step 6.3  
- Choose to record all supported resource types or specific ones (including IAM).

![Screenshot 2025-03-19 at 4 58 40 PM](https://github.com/user-attachments/assets/93f1bdc3-73fb-4357-976b-b9229d07e2e5)

---

#### 7. Set Up CloudWatch Alarms for Critical IAM Events

##### Step 7.1  
- In the CloudWatch console, navigate to your **Log Groups**, select your log group, and click **Search Log Group** on the top right.

![Screenshot 2025-03-19 at 5 51 17 PM](https://github.com/user-attachments/assets/124b2230-8f88-42f9-bfcd-4ed5d3a1d3df)

##### Step 7.2  
- Create a **Metric Filter** for CloudTrail logs that captures, e.g., root user activity or unauthorized API calls.

  **Example filter for root usage:**
  ```json
  { $.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent" }
  ```

![Screenshot 2025-03-19 at 5 45 28 PM](https://github.com/user-attachments/assets/bef943b8-572f-4fca-8004-a0b28c3d3c70)  
![Screenshot 2025-03-19 at 5 59 40 PM](https://github.com/user-attachments/assets/6cd11e6e-393c-423b-aef3-0b5d7f0a9fae)  
![Screenshot 2025-03-19 at 6 00 54 PM](https://github.com/user-attachments/assets/6729a455-3b26-4dc4-8e67-0d07b1b2d74d)

##### Step 7.3  
- Create a **CloudWatch Alarm** on this metric (e.g., trigger an alarm if the count is greater than 1 within a defined period).

![Screenshot 2025-03-19 at 6 17 30 PM](https://github.com/user-attachments/assets/63778bc3-7501-4a8b-886b-b0d6d9646b77)  
![Screenshot 2025-03-19 at 6 25 00 PM](https://github.com/user-attachments/assets/947def0a-db05-4e3c-9591-94ff501bb615)  
![Screenshot 2025-03-19 at 6 31 02 PM](https://github.com/user-attachments/assets/089fb8c7-e743-45be-8cba-4d6b32eb9126)

---

## 2. Securing AWS Core Services

### EC2 Security

Amazon EC2 instances provide raw compute power in the cloud, and securing them is similar to securing any server – with additional cloud-specific tools at your disposal.

### Insecure EC2 Example

- **Insecure Security Group Rules** – e.g., allowing SSH access from `0.0.0.0/0`:

  ![Screenshot 2025-03-19 at 6 59 53 PM](https://github.com/user-attachments/assets/39834a3e-94e9-43fd-a0e8-de57f02ba2fe)

- **Insecure Storage** – Encryption not enabled:

  ![Screenshot 2025-03-19 at 7 08 40 PM](https://github.com/user-attachments/assets/be6c89be-e3ce-4197-a69e-8afbb42f43ad)

#### Configuring Security Groups (Virtual Firewalls)

**Security Groups** are stateful firewalls that control inbound and outbound traffic for your EC2 instances. By default, a new security group has no inbound access and allows all outbound traffic. You should adjust security group rules to **allow only necessary inbound traffic** and deny all others by default:

- **Least Privilege Ingress:** Open only the ports required for your application and restrict the source IP ranges (e.g., `203.0.113.0/24` for SSH, rather than `0.0.0.0/0`).  
- **No Large Port Ranges:** Do not open overly broad port ranges (e.g., 1–65535).  
- **Outbound Rules:** By default, security groups allow all outbound traffic. Consider tightening them for high-security environments.

AWS security groups are **stateful**, so if you allow inbound port 443 from a client, response traffic is automatically allowed out. You can assign multiple groups to an instance for layered access rules. For an added layer, you can use **Network ACLs** at the subnet level, though security groups alone suffice for most cases.

---

### Editing the Insecure Security Group: launch-wizard-1

> **Note:** In this guide, the **launch-wizard-1** security group is considered insecure because it currently permits SSH (TCP, port 22) access from `0.0.0.0/0`.

**Step 1:** Navigate to **Security Groups** under the **EC2 Dashboard**.  
**Step 2:** Select the security group you want to edit, in this case **launch-wizard-1**.  

![Screenshot 2025-03-19 at 7 29 29 PM](https://github.com/user-attachments/assets/db7ecd9c-d83f-44e0-9ff7-f084376b7a6a)

**Step 3:** Review the Current Inbound Rule  
- The inbound rule allows SSH access (port 22) from `0.0.0.0/0`.  

![Screenshot 2025-03-19 at 7 32 31 PM](https://github.com/user-attachments/assets/4b7d121a-b758-4dc9-a3fd-b3ec92fc8447)

**Step 4:** Edit the Inbound Rule  
- Click **Edit inbound rules**.  
- Locate the SSH rule and change the source from `0.0.0.0/0` to your trusted IP range, e.g., `203.0.113.0/24`. You may change it to a specific IP as well.

![Screenshot 2025-03-19 at 7 35 01 PM](https://github.com/user-attachments/assets/f1bb2b34-0d23-4124-8194-16b5f08e8391)

**Step 5:** **Save the Changes**

**Step 6:** **Verify the Changes**  
- Test SSH from an IP **within** your IP range. In this case `203.0.113.0/24`:

  ![Screenshot 2025-03-19 at 7 42 54 PM](https://github.com/user-attachments/assets/66af1180-28cf-48f6-99ce-3473f8c05920)

- Attempt SSH from an IP **outside** that range: You should not be able to connect.

  ![Screenshot 2025-03-19 at 7 51 20 PM](https://github.com/user-attachments/assets/1230bb8c-dba7-495b-8406-414a0c74e8d6)

---

#### SSH Key Management (EC2 Key Pairs)

When launching Linux EC2 instances, AWS prompts you to select or create an **SSH key pair**. The key pair consists of a public key (stored by AWS) and a private key file (downloaded by you) for secure SSH authentication:

- **Creating a Key Pair:** In the EC2 console, under **Key Pairs**, create a new one. AWS will generate a `.pem` private key file — keep it secure!  
- **Secure Private Key Storage:** Limit file permissions (e.g., `chmod 400 MyKey.pem`). Never share this key via insecure channels.  
- **No Password SSH:** AWS Linux AMIs have SSH password auth disabled by default.  
- **Key Rotation & Hygiene:** If a key is compromised, delete it from AWS and update the instances to use a new key. Consider using unique keys per admin.

Alternatively, use **AWS Systems Manager Session Manager** for remote access without opening port 22 or managing SSH keys—helpful for strict environments.

---

### Encrypting EBS Volumes at Rest

Protect data on EC2 instance disks by enabling **EBS encryption**. Encryption is handled by AWS KMS, securing data at rest and all snapshots created from these volumes.

**Step 1: Understand EBS Encryption Basics**  
- EBS supports transparent encryption of volumes using AWS-managed or customer-managed KMS keys.

**Step 2: Enable EBS Encryption by Default**  
1. Navigate to **Account Attributes** → **Settings** → **Data protection and security** in the EC2 Dashboard.  
2. Locate **EBS encryption**.  
3. Click **Manage** next to EBS encryption, select **Enable**, and choose either the AWS-managed key (`aws/ebs`) or a customer-managed key.

![Screenshot 2025-03-19 at 8 11 02 PM](https://github.com/user-attachments/assets/31276513-716c-450d-a0ec-091c96fb0217)  
![Screenshot 2025-03-19 at 8 13 49 PM](https://github.com/user-attachments/assets/6adba95f-daa6-4ca5-9ada-423f67b561ce)  
![Screenshot 2025-03-19 at 8 15 27 PM](https://github.com/user-attachments/assets/a84a30e5-cacc-444c-a6d3-85216299bf5c)  
![Screenshot 2025-03-19 at 8 19 57 PM](https://github.com/user-attachments/assets/025f1c0e-b888-4fd5-b572-345b895148e9)

Once enabled, all newly created volumes in that region/account will be automatically encrypted.

---

### S3 Security

Amazon S3 is widely used for storing data—including potentially sensitive information. Misconfigurations can lead to major data leaks, so it’s essential to apply strict security controls. Below we cover blocking public access, enforcing encryption, and enabling logging on your S3 buckets.

---

#### Blocking Public Access

##### Step A1: Access the S3 Console

- From the AWS Management Console, navigate to **S3**.

##### Step A2: Select a Bucket

- Choose the S3 bucket you wish to secure (or create a test bucket if needed).

![Screenshot 2025-03-19 at 8 28 31 PM](https://github.com/user-attachments/assets/8c82b2f2-bd55-491d-b889-e903cf10b71b)

##### Step A3: Configure Bucket-Level Public Access Settings

- In the **Permissions** tab, scroll down to **Block public access (bucket settings)**.  
- Ensure all four settings are enabled:
  1. Block public ACLs  
  2. Ignore public ACLs  
  3. Block public bucket policies  
  4. Restrict public bucket access  

![Screenshot 2025-03-19 at 8 32 13 PM](https://github.com/user-attachments/assets/ed79b3f7-fcc6-4bdd-bd09-5eb356a0a168)

---

#### Enforcing Encryption for S3 Objects

##### Step B1: Access Bucket Properties

- On your S3 bucket page, click the **Properties** tab.

![Screenshot 2025-03-19 at 8 36 49 PM](https://github.com/user-attachments/assets/fc685338-ac73-417f-a5d9-ce359e281b37)

##### Step B2: Enable Default Encryption

- Under **Default encryption**, click **Enable** (or **Edit**).  
- Select **SSE-S3 (AES-256)** or **SSE-KMS** with your KMS key.

![Screenshot 2025-03-19 at 8 39 33 PM](https://github.com/user-attachments/assets/58ae32b7-e11d-493d-8572-99d77a65fba2)

##### Step B3: Verify Encryption

- Using AWS CLI or the S3 console, check if `"ServerSideEncryption": "AES256"` or `"aws:kms"` appears in object metadata.
- replace "your-bucket-name" with the bucket name you intend to check and replace "your-object-key" with any object in your logs.

  ```bash
    aws s3api head-object --bucket your-bucket-name --key your-object-key
    ```

![Screenshot 2025-03-19 at 8 49 47 PM](https://github.com/user-attachments/assets/1185cbdd-69f7-4808-b9b0-7a5d07d0a7ca)

---

#### S3 Logging & Auditing (Access Logs & Monitoring)

##### Step C1: Enable Server Access Logging

- In your S3 bucket’s **Properties**, scroll to **Server access logging** → **Edit**.  
- Choose a target bucket to store the logs (e.g., a dedicated `my-s3-logs` bucket).  
- Optional: set a prefix (e.g., `logs/`).

![Screenshot 2025-03-19 at 8 54 54 PM](https://github.com/user-attachments/assets/cbc04a4b-393e-48e4-8f05-188c207879d3)  
![Screenshot 2025-03-19 at 8 56 58 PM](https://github.com/user-attachments/assets/c1463c4c-bae2-4902-8bd3-61c374fda571)  
![Screenshot 2025-03-19 at 8 59 05 PM](https://github.com/user-attachments/assets/ce610f7f-35ed-442a-81ff-21466ee652f4)  
![Screenshot 2025-03-19 at 9 03 56 PM](https://github.com/user-attachments/assets/444b9d0e-ad82-43e7-a09b-cd1ec61286eb)

##### Step C2: (Optional) Use CloudTrail Data Events for S3

- In the CloudTrail console, enable **data events** for the specific buckets you want to monitor at the object level.

##### Step C3: (Optional) AWS Config Rules

- In AWS Config, enable rules like “s3-bucket-server-side-encryption-enabled” or “s3-bucket-public-read-prohibited” for ongoing compliance checks.

---

## 3. Logging & Monitoring with CloudTrail & CloudWatch

After implementing preventive security measures, it’s crucial to have strong logging and monitoring to detect suspicious activities and policy violations. This section covers setting up comprehensive auditing with CloudTrail and proactive alerting with CloudWatch. (If you followed the **IAM Activity Logging & Monitoring Setup** steps above, you already have a CloudTrail foundation.)

### Enabling AWS CloudTrail (Account-Wide Logging)

AWS CloudTrail should be enabled in every account and region to record all API activity:

- **Organization vs. Account Trails:** If using AWS Organizations, you can have an organization-wide trail. Otherwise, set up at least one trail per account.  
- **Multi-Region Trail:** Ensure CloudTrail is capturing events in all regions.  
- **Management Events:** By default, new trails log management events (control plane actions).  
- **Data Events (Optional):** Consider enabling data events for S3 or Lambda if object-level logging is needed.  
- **Trail Storage Location:** Use a secure S3 bucket with SSE enabled; consider restricting access to CloudTrail only.  
- **Log Retention & Validation:** Use log file validation and S3 lifecycle rules as needed.  
- **CloudTrail Insights (Optional):** Detects anomalous API activity.

### CloudWatch Alarms for Security Events

Logging alone isn’t enough—set up **CloudWatch Alarms** or metric filters on critical events:

- **Unauthorized API Calls:** Filter for `errorCode = "AccessDenied"` or `UnauthorizedOperation`.  
- **Root User Activity:** Alarm if the root account is used.  
- **Console Logins Without MFA:** Alarm on any login missing MFA.  
- **IAM & CloudTrail Config Changes:** Alarm on changes to IAM policies or attempts to disable CloudTrail.  
- **S3 Public Policy Changes:** Alarm if a bucket is made public.  
- **Security Group Changes:** Alarm if someone opens a port to `0.0.0.0/0` for SSH or RDP, etc.

Combine CloudWatch with:

- **AWS Config** for continuous checks.  
- **AWS GuardDuty** for advanced threat detection.  
- **Amazon EventBridge** for real-time triggers that can auto-remediate misconfigurations.

---

## 4. Simulated Attack Scenarios & Fixes

Below are three common AWS misconfiguration scenarios. Each demonstrates how attackers exploit weaknesses and how to mitigate or fix those issues.

### Scenario 1: Misconfigured S3 Bucket (Public Data Leak)

1. **Scenario:** A bucket is left publicly accessible with sensitive files.  
2. **Attacker’s View:** Attackers can list or download contents without credentials using a web browser or CLI with `--no-sign-request`.  
3. **Fix / Mitigation:**  
   - Immediately enable **Block Public Access** and remove any public ACLs or bucket policies.  
   - If sensitive data was leaked, follow your incident response plan.  
   - Use AWS Config or Security Hub to catch future public buckets quickly.

### Scenario 2: Overly Permissive IAM Role (Privilege Escalation)

1. **Scenario:** An EC2 instance has a role with broad permissions (e.g., `AdministratorAccess`).  
2. **Attacker’s View:** If they compromise the instance, they can retrieve temporary credentials and do anything in the account (e.g., read other S3 buckets, create new IAM users).  
3. **Fix / Mitigation:**  
   - Enforce **least privilege** for IAM roles—only grant necessary permissions.  
   - Monitor role usage (CloudTrail, GuardDuty).  
   - Revoke or rotate credentials if compromise is suspected.

### Scenario 3: EC2 Instance with Open Ports (External Attack)

1. **Scenario:** A test EC2 instance’s security group allows inbound traffic from `0.0.0.0/0` on a sensitive port (e.g., MySQL port 3306).  
2. **Attacker’s View:** They scan AWS IP ranges, find this open port, attempt brute force or exploit unpatched services.  
3. **Fix / Mitigation:**  
   - Restrict inbound rules to known IPs or internal services.  
   - Patch and harden the OS/application.  
   - Monitor open ports via AWS Config or third-party scanners.

---

## 5. Compliance & Best Practices Mapping

Finally, let’s map our security best practices to common compliance frameworks and industry best-practice standards to ensure your AWS environment not only is secure but also meets regulatory requirements.

### Alignment with CIS AWS Foundations Benchmark

- **CIS 1.x (Identity and Access Management):** Root account with MFA, no root API keys, IAM password policy, and MFA on all IAM users.  
- **CIS 2.x (Logging):** Multi-region CloudTrail, log file validation, CloudWatch integration.  
- **CIS 3.x (Monitoring):** Metric filters and alarms for unauthorized calls, root usage, IAM config changes.  
- **CIS 4.x (Networking):** Avoid wide-open ports for SSH/RDP, enable VPC flow logs.  
- **CIS 5.x (S3):** Default encryption, block public access, bucket logging.

### Meeting NIST SP 800-53 Controls

- **Access Control (AC):** IAM least privilege, MFA, security groups.  
- **Audit & Accountability (AU):** CloudTrail logging, log file integrity.  
- **Identification & Authentication (IA):** Unique IAM users, MFA for console access.  
- **System & Communications Protection (SC):** Encryption at rest (EBS, S3) and secure networking.  
- **Configuration Management (CM):** Monitored changes (AWS Config) and locked-down configs (SGs).

### SOC 2 Trust Services Criteria

- **Security & Confidentiality:** Strict access controls (IAM + MFA), encryption, logging, and alerting.  
- **Monitoring (CC7):** CloudTrail + CloudWatch Alarms provide continuous monitoring and anomaly detection.  
- **Logical Access (CC6):** Unique IAM principals, MFA, no shared credentials.  

### Other Frameworks (GDPR, ISO 27001, PCI DSS)

- **GDPR:** Emphasizes data protection by default (encryption, limited access, breach monitoring).  
- **ISO 27001:** Annex A.9 (Access Control), A.10 (Cryptography), A.12 (Operations Security)—all covered by IAM best practices, encryption, and logging.  
- **PCI DSS:** Restricts open ports, requires encryption (S3, EBS), logs all access, and monitors critical systems (CloudTrail + CloudWatch).

By following AWS best practices—least privilege, MFA, encryption, centralized logging, and continuous monitoring—you cover a substantial portion of the requirements across multiple compliance standards.

---

> **Future Topics:**  
> In upcoming updates to this guide, we will explore additional AWS services and security configurations such as **Lambda**, **VPC architecture**, **Amazon GuardDuty**, and more. Stay tuned for comprehensive, hands-on tutorials and best practices that further expand your AWS security knowledge.

## 📖 **Author**

Created by [Charlemagne](https://github.com/charlemagne-ai)
