# Unified Cloud Security Findings Dashboard

A multi-cloud security dashboard that aggregates and visualizes security
findings from AWS Security Hub and Microsoft Defender for Cloud in a
single platform. Secured using Microsoft Entra ID (OAuth2/OIDC).

------------------------------------------------------------------------

## 🚀 Overview

This project provides a **centralized view of cloud security posture**
by integrating multiple cloud providers and normalizing their findings
into a unified format.

It helps teams analyze vulnerabilities, track compliance, and monitor
security trends across environments.

------------------------------------------------------------------------

## ✨ Features

-   🔐 Single Sign-On using Microsoft Entra ID (OAuth2 / OIDC)
-   ☁️ Integration with:
    -   AWS Security Hub
    -   Microsoft Defender for Cloud
-   🔄 Normalized data model across providers
-   📊 Interactive dashboards (Chart.js)
-   🔍 Filtering and search on findings
-   📄 Pagination support (AWS NextToken, Azure nextLink)
-   👥 Persona-based insights (CISO, SecOps, Auditor views)

------------------------------------------------------------------------

## 🏗️ Architecture

    User → Entra ID (OIDC Login)
         → Spring Boot Backend (WebFlux)
             → AWS Security Hub API
             → Azure Defender API
         → Unified Response
         → Dashboard UI (Thymeleaf + Chart.js)

------------------------------------------------------------------------

## 🔑 Authentication

### User Authentication

-   Microsoft Entra ID (OAuth2 Authorization Code Flow)

### Backend API Authentication

-   AWS: IAM credentials\
-   Azure: Client Credentials flow (Access Token)

------------------------------------------------------------------------

## 📊 Dashboard Insights

-   Severity distribution\
-   Workflow status tracking\
-   Compliance overview\
-   Resource type breakdown\
-   Age-based vulnerability trends

------------------------------------------------------------------------

## 🛠️ Tech Stack

-   Java 21\
-   Spring Boot 3.x (WebFlux, Security)\
-   Spring Security OAuth2 Client\
-   AWS SDK v2\
-   Azure REST APIs\
-   Thymeleaf\
-   Chart.js\
-   Gradle\
-   MySQL (optional / future use)

------------------------------------------------------------------------

## ⚙️ Configuration

### Entra ID

    spring.security.oauth2.client.registration.azure.client-id=
    spring.security.oauth2.client.registration.azure.client-secret=

### AWS

    aws.accessKey=
    aws.secretKey=

### Azure

    azure.client-id=
    azure.client-secret=
    azure.tenant-id=

------------------------------------------------------------------------

## ▶️ Running the Application

``` bash
./gradlew bootRun
```

### Access

http://localhost:8080

------------------------------------------------------------------------

## 📁 Project Structure

    src/
     ├── controller/
     ├── service/
     ├── config/
     ├── model/
     └── templates/

------------------------------------------------------------------------

## 🚧 Future Improvements

-   Role-Based Access Control (RBAC)\
-   Caching for API responses\
-   Retry & rate-limit handling\
-   Dark mode UI\
-   Additional cloud providers support

------------------------------------------------------------------------

## 📌 Key Learnings

-   Multi-cloud API integration challenges\
-   OAuth2/OIDC authentication flows\
-   Data normalization across providers\
-   Reactive programming using WebFlux

------------------------------------------------------------------------

## 👨‍💻 Author

**Manigandan L**\
Associate Engineer
