+++
title = "I passed the eJPT!"
description = "I obtained my eJPT certification from eLearnSecurity"
type = ["posts","post"]
tags = [
    "certification",
    "ejpt"
]
date = "2022-06-20T11:14:00"
categories = [
    "certifications",
    "eJPT"
]
[ author ]
  name = "virtualtack"
+++

I am pleased to share that I recently passed the [eLearnSecurity Junior Penetration Tester](https://elearnsecurity.com/product/ejpt-certification/) certification exam on June 16!

<br/>

<center>
<img src="/images/ejpt-cert.png" style="height:420px"> 
</center>

## The Exam

According to [INE's website](https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester):

> The eJPT is a three day, 20 question exam, that focuses on challenging you to prove your skillset in penetration testing foundations including programming, networking vulnerabilities, web attack vectors, and a host of other entry level skills... Covering a host of skills which include entry level web penetration techniques, the eJPT provides you with the confidence and knowledge to begin training for more advanced penetration techniques and specialities.

## My Experience

There are thousands of reviews and suggested study guides for the eJPT on the internet. Thus, I will not try to reinvent any wheels with this post.

### Preparation

Before taking the exam, I spent about 3 weeks with INE's Penetration Testing Student learning path (read: online course). 

From my perspective and level of experience, the course material largely fell into four buckets: 

1. Introductory materials for elementary penetration testing tasks and concepts, such as computer networking, HTTP protocol basics, scripting with common languages like C++, Python, and Bash, as well as the use of basic tools like Burp Suite, Nmap, John the Ripper, and the Metasploit framework
2. The use of other, broadly outdated, tools[^1] 
3. Review of concepts and techniques I have previously learned (or been introduced to) via TryHackMe[^2] and/or miscellanious YouTube videos, blog posts, etc.
4. Networking

I emphasize #4 here, as, previous to my eJPT preparations, I had only engaged with network routing and live host discovery in theoretical/conceptual terms. I have not yet made my way through any of the TryHackMe network-based rooms, such as [Wreath](https://tryhackme.com/room/wreath) or [Throwback](https://tryhackme.com/network/throwback). 

Unfortunately, I wasn't able to access the preparatory "eJPT Exam Preparation" module (1 of 4 in the course), which, ostensibly, contains opportunities to practice network enumeration. According to this [Message from the INE CEO](https://ine.com/blog/message-from-ine-ceo), the company has encountered significant unforseen issues with migrating eLS' previously VPN-based labs to the browser-based INE teaching platform. While I don't think this is particularly egregious in and of itself, the timing was certainly unfortunate for me.

Indeed, I was only able to practice my network discovery and routing through the "Black-box Penetration Test 1" box at the end of the Penetration Testing Basics module. "Black-box Penetration Test" boxes 2 and 3, unfortunately, do not involve "secret" servers, but pre-identified and directly accessible hosts.

### Handy Resources
In addition to a smattering of reddit posts and similar incidental resources, I found the following guiding materials to be helpful in preparing for my exam:
* [KentoSec - How to Pass the eJPT](https://kentosec.com/2019/08/04/how-to-pass-the-ejpt/)
* [fdicarlo - eJPT](https://github.com/fdicarlo/eJPT)
* [Jarrod Rizor's eJPT Guide](https://jarrodrizor.com/ejpt-guide/)
* [grumpzsux's eJPT Notes 2022](https://github.com/grumpzsux/eJPT-Notes)
* [tejasanerao's eJPT-Cheatsheet](https://github.com/tejasanerao/eJPT-Cheatsheet)

**Note:** There is an enormous amount of overlap between each of these resources! Please don't feel like it is necessary to engage with all of them.

### Exam Impressions
All-in-all, I felt that the INE/eLS course and certification exam was an enjoyable and rewarding process. The exam, particularly, was fun and excellent preliminary preparation for future black-box exam scenarios, from both a methodological and emotional point of view. 

With only approximately 3 months of experience in infosec, offensive security, and cybersecurity more broadly, I was able to complete the exam in approximately 9 hours. After approximately 6 hours, I had secured enough points to pass the exam, though I wanted to take the opportunity to use the extensive (compared to what I am used to!) exam network and complete the remaining tasks that involved my weaker subject-areas, such as Windows host exploitation.

[^1]: This distinction is made with the knowledge that eLS/INE are [currently working on rolling out the eJPTv2](https://ine.com/blog/new-ejpt-coming-soon?utm%5C_source=linkedin&utm%5C_medium=organic&utm%5C_campaign=NeweJPTComingSoon&utm%5C_content=blog). The INE course for the new exam, [Penetration Testing Student v2](https://my.ine.com/CyberSecurity/learning-paths/61f88d91-79ff-4d8f-af68-873883dbbd8c/penetration-testing-student-v2), appears to have a significantly updated curriculum. 

[^2]: Relative to other platforms/courses, I have completed a relatively high number of THM rooms over the past two months. At the time of writing, I have completed 106 Rooms and have rank 11134. You can follow along with my progress by clicking [here](https://tryhackme.com/p/robscharf).