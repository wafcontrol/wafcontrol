[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# OWASP WAFControl

The **OWASP WAFControl** project provides a web-based dashboard and management interface for ModSecurity and the OWASP Core Rule Set (CRS).  
It simplifies installation, configuration, and operation of CRS and ModSecurity, enabling administrators and security engineers to deploy, monitor, and manage WAF rules more effectively.

WAFControl integrates rule management, attack monitoring, and configuration control into one centralized platform, making it easier to maintain strong web application security with reduced complexity.

![Attack](https://raw.githubusercontent.com/OWASP/www-project-wafcontrol/refs/heads/main/assets/images/crs.png)

## How To Use

The OWASP WAFControl installer automatically sets up **ModSecurity**, the **OWASP CRS**, and all required dependencies.  
It is recommended to install WAFControl on a clean server where these components are not yet installed.  

- If **Nginx** or **Apache** is not installed, the installer can install and configure them as well.  
- WAFControl uses **PostgreSQL** as its database backend, which will also be installed and configured automatically.  
- After installation, the web-based dashboard will be available to manage rules, monitor attacks, and configure CRS/ModSecurity.  

### Quick Installation

Run the following commands on your server:

```bash
curl -fsSL https://wafcontrol.org/download/install.sh -o install.sh
```

```bash
chmod +x install.sh
```

```bash
sudo ./install.sh
```



## WAFControl Features

- **Attack Control**:  
  - Real-time logging of attacks with detailed information.  
  - Dedicated **Critical WAF Attacks** section (e.g., SQLi, RCE, LFI).  
  - **Top Attacker** overview based on frequency of attacks.  

- **Rule Management**:  
  - Upload and edit CRS rules.  
  - Rule viewer categorized by rule IDs.  
  - Custom rule creation and management.  

- **CRS & ModSecurity Control**:  
- 
  - Version switcher to fetch and deploy different CRS versions from GitHub.  
  - GUI-based configuration for key ModSecurity and CRS settings, such as:  

## WAFControl Resources
- [OWASP WAFControl Project Site](https://wafcontrol.org/)
- [OWASP WAFControl Project Page](https://owasp.org/www-project-wafcontrol/)  

## Documentation
- [OWASP WAFControl Docs](https://wafcontrol.org/docs)


## Contributing to WAFControl

We welcome contributions from developers, researchers, and users.  
You can help us by:  
- Reporting bugs, usability issues, or false positives.  
- Suggesting new features and improvements.  
- Contributing code, documentation, or testing.  

👉 [Create an issue on GitHub](https://github.com/wafcontrol/wafcontrol/issues) to report bugs or request features.  
👉 [Join the OWASP Slack](https://owasp.org/slack/invite) and participate in the **#wafcontrol** channel to discuss and collaborate.  


## License

Copyright (c) 2025 OWASP WAFControl Project.  
All rights reserved.  

The OWASP WAFControl project is distributed under the Apache Software License (ASL) version 2.0.  
See the enclosed [LICENSE](./LICENSE) file for full details.
