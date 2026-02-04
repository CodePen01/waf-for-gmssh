# WAF-FOR-GMSSH (Nginx-Lua Edition)

**A high-performance dynamic WAF powered by `ngx_lua`.**

- en_US [English](README_EN.md)
- zh_CN [简体中文](README.md)
---

## 📖 Description

This project is a high-performance security engine tailored for the **GMSSH** ecosystem. By integrating the `ngx_lua` module, it performs real-time traffic filtering during the Nginx Access phase, providing deep defense against SQLi, XSS, and CC attacks.

## 🌟 Background

As a developer managing multiple servers, I recognized that mainstream WAF products with high licensing fees are not friendly to individual developers and small businesses. While seeking a more cost-effective security solution, I came across the **GMSSH Developer Center**.

GMSSH's open ecosystem access, streamlined review process, and official SDK allowed me to focus entirely on building core security logic and refining UI interactions. Based on this, I developed this WAF plugin specifically for GMSSH, which has been officially launched in the application center.

**Notably:** While this project is deeply adapted for GMSSH, it also supports running in **standard Linux environments**. No code modifications are required—simply deploy the Lua scripts to the Nginx module to achieve the same protection capabilities.

## ✨ Enhanced Features

### 1. Advanced Deployment

* **Multi-version Nginx Compatibility**: Breaks through original environment limitations, perfectly adapting to dozens of compiled versions from Nginx 1.12.0 to 1.28.1.

* **Zero Platform Dependency**: The code implementation is fully decoupled, with no specific platform binding, ensuring stable operation in various standard Linux environments.

### 2. Smart Health Check

* **Automatic Anomaly Verification**: New environment detection scripts automatically verify Nginx service status, Lua version compatibility, and the integrity of key dependency libraries.

* **Quick Fault Localization**: When abnormalities occur in the running environment, the system provides intuitive error prompts and guides one-click management or version switching, greatly reducing operational thresholds.

### 3. Precision Defense

* **High-precision IP Library Integration**: Introduces a more precise IP geolocation library, where alarm logs not only display attack types but also accurately identify the attacker's country, province/city, ISP, and location information.

* **Comprehensive Regional Restrictions**: Supports extremely detailed geo-fencing strategies, allowing one-click blocking/allowing of all overseas regions, all domestic provinces/cities, or custom selection of specific international cities (such as New York, London, Tokyo) and domestic cities.

### 4. UX & Internationalization

* **Simplified List Management**: Reconstructed blacklist/whitelist logic, supporting dynamic updates for multiple types such as IP, UA, URL, and human-machine verification, with batch setting modes for one-place addition and multiple-place reuse.

* **Native Internationalization Support**: The interface is fully adapted for multi-language switching, providing standard Chinese-English bilingual interaction for dashboards, logs, and configuration items, meeting global operation and maintenance needs.

* **Visual Policy Configuration**: The global settings module has been logically split, modularizing function switches for anti-CC, request compliance, anti-injection, resource abuse prevention, etc., with intuitive operation, truly achieving zero-documentation, ready-to-use functionality.

### 5. Real-time Analytics

* **Multi-dimensional Data Dashboard**: Provides a comprehensive dashboard, real-time display of interception trends (minute/hour level), today's interception Top 10 IP/URL, and detailed real-time interception logs.

* **Omni-channel Instant Alerts**: Supports multiple alert methods such as DingTalk Webhook, ensuring that administrators can obtain detailed attack packets and source information in real-time via mobile devices when under attack.

## 🚀 Core Functionalities

* **Ultra-High Performance**: Fully utilizes LuaJIT performance, achieving near "zero latency" transparent protection for business access.
* **Transparent Logic**: Filtering logic is fully open-source, supporting developers to highly customize defense rules according to business needs.
* **Smart CC Protection**: Based on `Shared Dict` shared memory mechanism, achieving precise concurrent request and access frequency control.
* **Seamless Integration**: Deeply adapts to the GMSSH management system, significantly reducing the entry threshold for security operations and maintenance.

### 📊 1. Security Dashboard

* **Global Situation Awareness**: Real-time monitoring of total historical interceptions, today's request volume, today's interception count, and cleaned traffic, with clear defense effects at a glance.

* **Multi-dimensional Data Analysis**: Built-in real-time interception monitoring (requests vs. attacks), today's interception Top 10 (IP/URL), real-time interception logs, and historical trend analysis, helping with precise decision-making.

  ![img](./img/1.png)

### 🛡️ 2. Comprehensive Protection

* **Website Defense Management**: Supports independent protection switches for multiple sites, flexible configuration of global or custom defense strategy modes.
* **Deep Blacklist/Whitelist**: Supports multi-dimensional blacklist/whitelist settings for IP, UA, URL, etc., supporting CIDR address segments and batch import of IP ranges, with precise access control.
* **Regional/Traffic Restrictions**: Supports refined geographic location interception (allow/block) for domestic and foreign provinces/cities, with built-in traffic restrictions, exclusive restrictions, and custom rule engines to meet complex business needs.
* **Unique IP address database**, updated monthly with the latest IP database.

![img](./img/2.png)

![img](./img/3.png)

### ⚡ 3. One-Click Global Configuration

* **Scenario-based Defense Split**: Logically split for different attack types, including:
* **Anti-CC Attack**: Supports URL-level CC defense, URL human-machine verification, and API interface-specific defense.
* **Standard Defense**: Request compliance verification, SQL injection defense.
* **Resource Protection**: Prevention of resource abuse, prevention of automated crawler scanning.
* **Content Security**: Sensitive word filtering and directory scanning defense.


* **Ready-to-Use**: All configurations adopt a switch design, no need to write complex scripts, achieving zero-threshold security operations and maintenance.

### 🔔 4. Intelligent Alerting

* **Multi-channel Linkage**: Built-in DingTalk and standard Webhook alert support, real-time push of attack events, ensuring risks are perceived at the first time.
* **CDN Deep Adaptation**: Supports accurate acquisition of real access IP from Header lists (such as `cf-connecting-ip`, `x-forwarded-for`, etc.), perfectly compatible with various mainstream CDN environments.
* **HW Mode**: Supports one-click activation of "read-only protection mode", providing the highest level of security reinforcement during special sensitive periods.

![img](./img/4.png)


---

## 🚀 Quick Start

### 1. Get the Code

```bash
git clone https://github.com/CodePen01/waf-for-gmssh.git

```

### 2. Deployment Options

#### **Option A: Production Environment Integration (Standard Nginx)**

1. Ensure Nginx has `lua-nginx-module` compiled.
2. Place the `lua` scripts in the Nginx configuration directory.
3. In the `http` section of `nginx.conf`, introduce the core interception logic through `access_by_lua_file`.

#### **Option B: GMSSH Developer Debugging**

1. **Start Backend Service:**
```bash
cd gmssh-for-waf/waf-backend/backend
# Create and activate virtual environment
python3 -m venv .venv && source .venv/bin/activate
# Install dependencies
pip3 install -r requirements.txt
# Start backend process
python3 main.py

```


2. **Application Center Configuration:**
* Open **Development Debugging Tool**, create a front-end and back-end application.
* **Application Name:** `kele/safewaf`
* **Access Address:** Download the front-end project to local, start with VSCode "Live Server", and enter the corresponding local access address.
* **Socket Path:** Enter the Socket path generated when the above Python backend service starts.


3. **Complete Startup:** After clicking confirm, you can start debugging and running WAF in the GMSSH environment.



## 📅 Roadmap

This project is not a mere "code reproduction". I aim to build it into a truly useful, inclusive, and free open-source security tool. Here are my development priorities, and I welcome like-minded friends to participate

* **Dockerization:** I am building Docker images with the goal of achieving one-click image pull to complete cloud deployment of WAF nodes, facilitating multi-site and cluster security management for everyone. Working on a Docker version for easier cloud management and rapid deployment.

* **Multi-OS Support:** Next, I will invest effort in optimizing performance on NAS systems (Synology, QNAP, etc.), legacy CentOS (below version 7), and domestic server operating systems, ensuring all environments can enjoy equal protection. Expanding native support to NAS systems, legacy CentOS, and domestic server OS.

* **Performance Tuning:** Planning to further refactor the core Lua interception logic to reduce CPU overhead under high concurrency while maintaining continuous updates to the attack fingerprint library. Continuous refactoring to reduce CPU overhead and keep attack fingerprint libraries up-to-date.


## 🤝 Feedback

This project is driven by community developers. If you have any optimization suggestions, find bugs, or have new protection scenario requirements:

1. Please directly **[submit an Issue]** in this project.
2. Welcome to submit **Pull Request**, and every line of your code contribution will be included in the project contributor list.

## ⚖ License

This project is open-sourced under the [GPL-3.0 License](https://opensource.org/licenses/GPL-3.0).
When referencing or secondary developing, please consciously abide by the agreement requirements and retain attribution to the original author and the above reference sources.

## 🛠 Acknowledgments

In line with the original intention of "embracing open source and not reinventing the wheel", this project has deeply referenced mature Nginx-Lua solutions in the industry during the research and development process.

### **Statement of Gratitude:**

The core architecture and rule filtering logic of this project have mainly benefited from the following excellent open-source achievements:

* BT.cn WAF Core Script: This project inherits its robust filtering algorithm and has conducted in-depth variable adaptation and underlying performance optimization for the GMSSH operating environment.
* loveshell/ngx_lua_waf: Referenced its classic Lua interception processing flow design.

**Special Note:**
During the early development and compatibility testing phase, to ensure logical connection with mainstream operation and maintenance environments (such as the BT ecosystem), some variable naming conventions were retained in the code. Currently, the open-source version has completed preliminary standardized cleaning and reconstruction. Tribute to all open-source pioneers.
GMSSH contacted us, and we actively cooperated to modify and improve some code logic.
