# Mesh Security


  [![Build Status](https://wso2.org/jenkins/view/cellery/job/cellery/job/mesh-security/badge/icon)](https://wso2.org/jenkins/view/cellery/job/cellery/job/mesh-security/)
  [![GitHub (pre-)release](https://img.shields.io/github/release/cellery-io/mesh-security/all.svg)](https://github.com/cellery-io/mesh-security/releases)
  [![GitHub (Pre-)Release Date](https://img.shields.io/github/release-date-pre/cellery-io/mesh-security.svg)](https://github.com/cellery-io/mesh-security/releases)
  [![GitHub last commit](https://img.shields.io/github/last-commit/cellery-io/mesh-security.svg)](https://github.com/cellery-io/mesh-security/commits/master)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  
In Cellery, each Cell is considered as a unique trust domain and each Cell has it's own Secure Token Service (STS) which the workloads can use to communicate in a trusted manner with each other. Not only authentication, but also fine grained authorization requirements  can be achieved for the purpose of inter and intra Cell communications. 


## Edge Security 

Cellery mesh has an entry point to the data plain which we call as the global gateway. Cell developers publish their global APIs to global gateway which ultimately are be exposed through global gateway. These APIs can be protected or unprotected. In a case if the APIs are protected, the end user retrieves an edge token to invoke the API through global gateway.

This token will be an opaque token and end users uses this token to invoke APIs. Upon invoking APIs, global gateway issues a JWT token to the backend service, which is exposed through the Cell gateway after validating the edge token. 

<div align="center"><img src ="./docs/images/edge-security.png" width="70%"/></div>


## Cell Security

Upon issuing the JWT by global gateway to the backend, the request flows through Cellery Mesh. Each data plane component in Cellery has a sidecar attached to it. The requests which reaches components are intercepted by the STS through sidecars.

<div align="center"><img src ="./docs/images/intracell.png" width="60%"/></div>

## Request Flow


Below sequence diagram elaborates the flow of a request within Cellery mesh while interacting with two Cells

<div align="center"><img src ="./docs/images/token-flow.png" width="70%"/></div>

## Inter Cell Communication


<div align="center"><img src ="./docs/images/inter-cell.png" width="70%"/></div>

Cells have trust relationship with each other. When a workload in one Cell invokes a service in another Cell, issuer  
Cell’s STS issues a token addressing the destination Cell passing user context obtained through the original edge token. Destination Cell validates the token using issuer Cells' keys. In a case key is not cached, the destination Cell calls the JWKS endpoint of the issuer Cell and retrieve keys.  


## Configuring Cell STS.


| Configuration Element     | Description                                           |
| ------------------------- | ----------------------------------------------------- |
| globalJWKS                | Global JWKS endpoint which is the APIM JWKS endpoint  |
| enableSignatureValidation | Enable / Disable signature validation of tokens       |
| enableIssuerValidation    | Enable / Disable issuer validation of tokens.         |
| enableAudienceValidation  | Enable / Disable audience validation of tokens        |
| enableAuthorization       | Enable / Disable authorization evaluations            |
| OPAQueryPrefix            | OPA query prefix. Default one is data/cellery/io .(This is the package you are writing the policy).|    |



## Policy based access control.

An [Open Policy Agent (OPA)](https://github.com/open-policy-agent/opa) instance is running alongside with each STS. The default Cellery authorization mechanism is based on OPA quries. 

### Sample

To start with, deploy the [review sample](https://github.com/cellery-io/sdk/tree/master/samples/product-review). When you invoke the service, you will get the expected results as the response. 

In order to apply a policy, edit the policy by editing the ConfigMap customer-products-policy. 

1) Open the policy configured for customer products Cell. 
```
kubectl edit configmaps customer-products--sts-policy
```
2) Add the below policy instead of default policy 

```
 package cellery.io
   customer_products__categories_service_allow = false

   customer_products__categories_service_allow {	
     input.source.cellName="NonExistingCell"
   }
```
  		
  This policy denies requests to customer-products--categories-service if the source Cell name is not equal to **“NonExistingCell”**. After configuring this policy, wait for few seconds to get this deployed in OPA. (you can observe the logs of OPA container of customer-products-sts pod). Invoke the service. In the response, below error can be observed as a part of the response.

```json
"category" : {
    "id": "3",
    "error": "category service is currently unavailable"
},
```

The customer--products--categories-service denies the request since the source Cell is not **"NonExistingCell"**. Reviews Cell failed to retrieve response from this service since reivews Cell is not allowed to talk to customer-products Cell. 

Format of the input json to OPA server can be found in [here](docs/input.json)

**Note : The Rego policies should be written by replacing the "-" in the service name with "_" since "-" is a preserved 
character in Rego. Also the service name should be followed by a "_allow" in Rego rule**

## Repo Structure
 
 Components comprise of Cell and global components whereas docker directory contains docker files for building each 
 components. Below is the source tree of mesh-security
        
        
        ├── components
        │   ├── cell
        │   │   └── Cell sts (Cell STS server)
        │   ├── global
        │   │   ├──extensions used in global APIM (JWT issuer to backed)
        │   │   ├──token endpoint(Customized token endpoint for retrieving tokens for testing purposes)
        │   │   └──token endpoint core (core logic of customized token endpoint in global plane)
        │   └── orbit (gogoproto orbit which is used as a dependency to Cell STS)
        └── docker
            └── sts docker (Docker file to build Cell STS image)

## Contribute to Cellery Mesh Security

The Cellery Team is pleased to welcome all contributors willing to join with us in our journey.

### Build from Source

#### Prerequisites 

To get started with building Cellery Mesh Security, the following are required.

* Docker
* Git
* JDK 1.8 or higher
* Maven
* GNU Make 4.1+
		
#### Steps
Clone mesh-security using below command.
```
git clone https://github.com/cellery-io/mesh-security.git
```
Build the repo using make file.
```
make build-all
```
### Issue Management

Cellery Mesh Security issue management is mainly handled through GitHub Issues. Please feel free to open an issue about any question, bug report or feature request that you have in mind. (If you are unclear about where your issue should belong to, you can create it in [Cellery SDK](https://github.com/cellery-io/sdk).)

We also welcome any external contributors who are willing to contribute. You can join a conversation in any existing issue and even send PRs to contribute. However, we suggest to start by joining into the conversations and learning about Cellery Mesh Security as the first step.

Each issue we track has a variety of metadata which you can select with labels:

* **Type**: This represents the kind of the reported issues such as Bug, New Feature, Improvement, etc. 
* **Priority**: This represents the importance of the issue, and it can be scaled from High to Normal.
* **Severity**: This represents the impact of the issue in your current system. If the issue is blocking your system, and it’s having an catastrophic effect, then you can mark is ‘Blocker’. The ‘Blocker’ issues are given high priority as well when we are resolving the issues. 

Additional to the information provided above, the issue template added to the repository will guide you to describe the issue in detail therefore we can analyze and work on the resolution towards it. We appreciate to fill the fields mostly as possible when you are creating the issue. We will evaluate issues, and based on the label provided details and labels, and will allocate to the Milestones.
