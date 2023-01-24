+++
title = "I passed the PNPT!"
description = "I recently obtained my PNPT certification from TCM Security"
type = ["posts","post"]
tags = [
    "certification",
    "pnpt",
    "tcm",
]
date = "2022-11-28T11:35:00"
categories = [
    "certifications",
    "PNPT",
]
[ author ]
  name = "virtualtack"
+++

I am happy to share that I recently passed the Practical Network Penetration Tester certification exam on November 6!

<br/>

<center>
<img src="/images/pnpt-cert.png" style="height:420px"> 
</center>


## The Exam
According to [TCM's website](https://certifications.tcm-sec.com/pnpt/):

> The PNPT certification exam is a one-of-a-kind ethical hacking certification exam that assesses a student’s ability to perform an external and internal network penetration test at a professional level.  Students will have five (5) full days to complete the assessment and an additional two (2) days to write a professional report.

## My Experience

### Preparation
In the run-up to my more intensive and direct exam preparation, I largely continued along my learning trajectory on TryHackMe (with a bit of HacktheBox sprinkled in, for good measure). As of the time of writing, I am ranked 3612 on THM, with 204 rooms complete, including the Wreath network and the "Compromising Active Directory" series.

In terms of preparations for the PNPT itself, I completed the vast majority of the 5 provided/recommended training modules, as well as *Movement, Pivoting and Persistence* by [Joe Helle](https://medium.themayor.tech/). Taking my previous experience with CTFs (and preparation fatigue!) into consideration, I made the decision to complete only the sections of the Windows and Linux Privilege Escalation courses that contained unfamiliar vectors, leaving the remainder for after the exam (or, had I failed, my second attempt). 

A quick **note**: I completed all of my course preparations in such a way that I would not need to use Metasploit in applying the concepts/techniques that I learned. For metasploit-specific modules, I spent time ensuring that I could perform the same enumeration/exploitation with other tools.

#### Practical Ethical Hacking - The Complete Course
TCM's PEH course, its most popular offering, covers a huge range of topics for the beginning penetration tester. From networking to python scripting, to OSINT approaches, buffer overflow exploitation, as well as Windows Active Directory and web application pentesting, this course contains a wealth of useful training for beginners in offensive security. Personally, I found the introduction to buffer overflows and Active Directory portions of the course the most helpful. 

More specifically, the PEH course's AD section facilitates students standing up and configuring their own local Active Directory network environment. Coming into the course, my homelab ambitions remained solidly below the top priorities in my to-do list (much to my own detriment!). Paired with the MPP course (more below), I came out of my PNPT prep with a fully functioning homelab, complete with multiple nested virtual networks. I also gained proficiency with the creation and configuration of PfSense routers, which has allowed me to keep my network flexible and neatly segmented.

#### Open-Source Intelligence (OSINT) Fundamentals
While OSINT represents the segement of the training that I am the least organically interested in, I found several valuable tools and methodologies in this course that I will be carrying forward with me. While relatively simple, I found the challenges entertaining. 

#### External Pentest Playbook (EPP)
I found this course a bit more directly relevant to my development, as it introduced me to popular/common external attack vectors, as well as methods for compiling findings into a professional-grade report - the latter of which I had not yet had an opportunity to do with any real seriousness in my studies to this point. While short, I found this course to be very worthwhile. 

#### Windows Privilege Escalation for Beginners
As mentioned earlier, I did not finish 100% of this course before taking my exam. Instead, I focused on the topics that were unfamiliar to me (and/or for which I had gaps in my notes). In particular, I found the modules on Windows System for Linux, Token Impersonation, Alternate Data Streams, and the Windows Registry to be most helpful.

#### Linux Privilege Escalation for Beginners
Similar to the Windows PrivEsc course, I did not complete this in full before my exam date. I believe that my CTF experience gave me a larger advatage in Linux PrivEsc than with regard to Windows systems, simply due to the relative popularity of each. That said, I found the section on Docker container exploitation to be the most valuable going forward.

#### Movement, Pivoting and Persistence (MPP)
Behind the PEH flagship course and EPP, I found the MPP course the most useful of the recommended TCM offerings. Not only did the course provide a solid refresher on AD network enumeration, it facilitated the expansion of my homelab. I found the sections that directly or indirectly dealt with AV/AM evasion to be especially helpful, as well. While I found the Covenant C2 framework frustrating to use, I appreciate the introduction to it nonetheless.

### Exam Impressions
On the whole, I really enjoyed the PNPT exam experience. As someone who has only been pursuing penetration testing/offensive security for approximately 8 months, I found the difficulty level to be excellent, relative to my skills. While I got stuck on one section of the exam for an extended period of time (and grappled with the ensuing emotional challneges), I finished with time to spare. I enjoyed the diversity of challenges presented by the exam and feel like I was able to use skills developed both before and during my immediate preparation, and I found myself thinking of additional possible network attack vectors for days after my exam ended! 