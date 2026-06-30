# ThreatBadger

<img alt="ThreatBadger Logo" src="/webapp/assets/img/logo-large.png" width="200px" align="center"/>

Interface to query multiple OSINT sources and internal data sources when researching IOC or IOAs. Currently IPv4, IPv6 Domains, Emails, and Hashes are supported against public OSINT sources as well as internal MISP and ElasticSearch databases.

You can also connect to an ElasticSearch SIEM to search your logs for any IOC/IOAs.

## Installation
- Copy all files to your server and configure the required settings in webapp/config.php
- Use docker-compose.yml to setup environment.  Currently is setup in an insecure method.  Recommend putting it behind a reverse proxy or installing your own certificates.
- Start and build the docker container 'docker compose up -d --build'
> All files are copied to the container on build, so modifications to the files in webapp will not be active until the next docker build.

## Lookup
Numerous OSINT sources can be defined to search IOCs.  Some sources require an API key on the settings page while others are free resources.  You can also include your own list of raw files to search through, such as IP or Domain lists on github.
<img alt="ThreatBadger Lookup" src="/Screenshots/Lookup.png" align="center"/>

## Hunt
You can connect an elasticsearch database to hunt for IOCs in logs.
<img alt="ThreatBadger Lookup" src="/Screenshots/Hunt.png" align="center"/>
