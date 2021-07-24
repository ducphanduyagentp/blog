---
title: "UB Lockdown V3"
date: 2017-12-04 23:15:24 -0500
categories: [Incident Response]
tags: [incident response, blue team, rit, ccdc]
author: Duc Phan
excerpt-separator: <!--more-->
---

The weekend before Thanksgiving, I had the chance to play at Lockdown v3, an incident response competition held at University of Buffalo by [UBNetDef](https://lockdown.ubnetdef.org).

<!--more-->

## Overview
- This is a defense-only competition
- There are 6 people per team.
- Each team is given access to an infrastructure with basic components of an enterprise network:
  + Windows and Linux client machines
  + Web server(s)
  + Active Directory/DNS server(s)
  + FTP server
  + Mail server
  + Databases
  + A router. In this competition, it is a pfSense router.
- While blue teams (competitors) trying to defend the infrastructure under the attack of red team, blue teams have to complete technical and business tasks (called **injects**) within a certain amount of time. This increase significantly the pressure of the competition since the scoring are 50/50 for up-time and injects.
- During the competition, there are meeting between team captain and C-level people for information inquiry about the work progress.
- Blue teams are required to turn in an incident response report as the final inject at the end of the competition.

## Competition Time

My responsibilities in a nutshell:

- Keep the web servers up and running and maintain the communication between the web application and the databases.
- Keep the Linux clients ping-able from the scoring engine.
- Keep things clean and properly configured.
- Record red-team activities for incident reporting.

I started out by changing the default passwords on all the machines that I was on. Firstly, I changed password of the root users and users that are used to login to other machines to avoid password reuse. However, I **stopped changing the passwords** when I realized that there were so many users and I couldn't figure out a way to automate this process without hard-coding it. I didn't even proceed to audit those users. This is a huge mistake.

I tried to deploy my firewall script on the machines serveral times. It didn't work perfectly. I ended up taking them down, leaving the machines without firewall. They did not get hit hard until the end of the competition, when red team tried to burn the scoreboard. Still, it is another big mistake where I could have avoided by better preparation.

Here are some of my findings before red team burning the scoreboard:

- Backdoor in ~/.bashrc that filters out red-team activities from the output of commands like `netstat, ps`.
- Reverse shell backdoor in `/root`
- Backdoor ssh-key that allow red-team to login without password.

Towards the end of the competition, red-team attempted to delete the host routing table on the Linux clients, making it un-ping-able from the scoring engine. The solution was to rebuild the routing table. It took me a while as I didn't expect to work with host routing table. This is a new thing that I've learned during the competition.

## Lesson Learned

tl;dr:

- Firewalls ftw.
- Don't rush. Know what you do.
- Have a plan, stick with it.
- Look carefully.
- Change default credentials. There is a potato out there died for each of the unchanged credential.


### Gameplay

1. **IF YOU HAVE A PLAN, STICK WITH IT. IF NOT, MAKE ONE, AND STICK WITH IT**: I had a plan. I even told myself that I would be panicking during the competition and that's what the 5-minute plan was for. I ended up carrying out portions of the plans in no order. That made me panic even worse towards the end of the competition.
2. It is easy to overlook obvious things when being under pressure. I skipped things that I was supposed to investigate: ansible scripts, redundant services that are actually backdoors, .bashrc, aliases, all kind of things in this planet.
3. There is a lot going on this kind of competition and even in real life situation. For me, it is often difficult to distinguish between malicious and non-malicious files/processes/configurations/etc during the competition and at that time, I did not know what to do with those things and proceeded to do research on things that I could have spent time learning before the competition. I think one of the best way to truly understand something is to build it from scratch and install components and monitor the changes in the systems. In that way, I can figure out different "states" of the systems, and whether something is malicious or not.

## The techy bits

1. **CHANGE DEFAULT PASSWORDS**: Just change it. If there's too much work, try to find a way to automate the process.
2. Have a working firewall script. My scripts break on all the competitions that I have ever been to.
3. The scored web application communicates with the databases. When the databases are down, we lose points for the web application as well. This means it's not about just defending separate machines, but keeping the communication between the components is also critical.
4. Monitoring file integrity is critical.
5. Check for PAM backdoor.
