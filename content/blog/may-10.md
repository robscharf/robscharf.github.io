+++
title = "I passed the OSCP!"
description = "My thoughts and experiences..."
type = ["posts","post"]
tags = [
    "certification",
    "oscp",
    "offsec",
]
date = "2023-05-16T12:05:00"
categories = [
    "certifications",
    "OSCP",
]
[ author ]
  name = "virtualtack"
+++

I am happy to share that I recently passed the the Penetration Testing with Kali Linux certification exam on May 10 (on my first attempt)!

<br/>

<center>
<img src="/images/oscp-cert.png" style="height:420px"> 
</center>


## The Exam
According to [OffSec's website](https://www.offsec.com/courses/pen-200/):

> The industry-leading Penetration Testing with Kali Linux (PWK/PEN-200) course introduces penetration testing methodologies, tools and techniques via hands-on experience and is self-paced. Learners who complete the course and pass the exam will earn the OffSec Certified Professional (OSCP) certification which requires holders to successfully attack and penetrate various live machines in a safe lab environment. The OSCP is considered to be more technical than other ethical hacking certifications and is one of the few that requires evidence of practical penetration testing skills.

## My Experience

### Preparation
Between [finishing the PNPT](http://localhost:1313/blog/november-28/) and beginning OffSec's PEN200 course, I completed 20 HackTheBox entries from TJNull's famous list. If you find that you're struggling with boxes from the list, I highly recommend taking a look at [IppSec's OSCP Prep playlist](https://www.youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf), which covers dozens of boxes included in the list. 

In addition to the aforementioned boxes, I participated in HTB's Open Beta Season as part of the [DevotedOccultists](https://app.hackthebox.com/teams/overview/5487) team.

### PEN200
Due to the timing of my PEN200 adventure, I had the unique experience of following both the "2022" and "2023" version of the course. In case you are unfamiliar, in mid-March of 2023, OffSec (formerly Offensive Security) [released an updated version of the PEN200 course](https://www.offsec.com/offsec/pen-200-2023/) - the first in approximately three years. 


<center>
<img src="/images/pen200.png" style="height:420px"> 
</center>
<br/>

#### PEN200 2022 - Course
Of the "old" course, I found the Bash Scripting, Buffer Overflows, File Transfers, and Port Redirection and Tunneling modules to have contained the most useful content. While none of these topics were new to me (nor should they be to anyone beginning PEN200), the course contents provided insight into new techniques and/or approaches to underlying core concepts. Equally, I found that - while sometimes tedious - the topic exercises provided effective bite-sized practice tasks, as well as the opportunity to glean a bit of insight into OffSec's particular style of testing understanding of a given concept or topic.

As mentioned above, I found a lot of value in completing the course modules devoted to Buffer Overflows (Introduction, Windows, Linux) and their associated exercises. Despite the Buffer Overflow sections being removed from the course and exam (more on that later) *after* I had completed them, I would recommend similar materials for future OSCP-seekers. Coming into the course with little experience related to binary exploitation (nor with lower-level programming, more broadly), the Buffer Overflow sections helped me to deepen my understanding of how applications (and, by extension, computers) work more broadly.

I completed 100% of the 2022 exercises, making me eligible for bonus points with a sufficient number of lab machines rooted.

#### PEN200 2022 - Labs
Before the "old" labs were retired in mid-April, I managed to complete 47 of the 75 available machines (*without* doing any of the guided `sandbox.local` network). Unfortunately, I did not have time to delve into the Development or Administrator subnets.

When compared with competing offerings (see below), the size and scale of the PEN200 labs are quite significant and commonly understood to represent the lion's share of course's value. My experience was largely consistent with this. In addition to the opportunity to practice a wide variety of enumeration and exploitation techniques, the sheer size of the lab required a lot of preliminary scanning and host identification (which is rarely needed for individual CTF machines and/or small networks) - skills that are difficult to practice in a blind lab setting. 

Throughout my lab experience, I benefitted from the accompanying Discord channel. While I did not always find the Community Mentors to be exceedingly helpful in navigating the lab's idiosyncracies, I did find many of the pinned messages to be useful and support from fellow students (especially when delving into archived messages, found via the channel search function) was valuable and plentiful. Equally, I did not engage much with the now-deprecated forums.

> **Note:** I have not yet explored HackTheBox's Academy offerings or the associated CPTS certification, which are relatively new. My understadning is that they are popularly regarded as having similar, if not more profound, substantive depth than PEN200/OSCP.

#### PEN200 2023 - Course
The updated "2023" PEN200 course and labs were released about two months before I would ultimately take the OSCP exam. In addition to a reimagined curriculum, each PEN200 learning module was standardized, providing a linear path from introduction to capstone exercises (successfully completing the latter of these ostensibly indicates that a student is proficient with the entire module.)

As part of the updated course curriculum's introductory modules, OffSec has included a variety of practical but non-technical topics. While I personally found the treatment of some of the pedagogical themes introduced in the Effective Learning Strategies to have been a bit superficial, I commend OffSec in its decision to develop this subject area, as I agree that it is underdeveloped in the field when considering its potential benefit to students. I found the report writing section to be informative and well developed, if not groundbreaking - I imagine this section is quite useful to anyone who hasn't written a "professional" penetration test report before taking the course.

The expansion/disagregation of the Web Application Attacks and Active Directory modules in the updated curriculum is a clear improvement and effectively represents the character of most course updatesm, in terms of increasing the breath and depth of material. While I didn't complete 100% of the updated topic exercises before taking my exam, I did fully complete those associated with modules 7-10 (web application attacks) and 21-23 (Active Directory), while finishing over 80% of modules 12-13 (locating and fixing public exploits) and module 18 (port redirection and SSH tunneling).

#### PEN200 2023 - Labs
The 2023 update included a reimagining of the OSCP lab environment that had become notorious in the infosec community. No longer are students be dropped into a network with dozens of hosts, with mysteriously interdependent hosts and Active Directories scattered throughout. Instead, OffSec now provides 6 "challenge" networks divided into two categories: 
- Challenges 1-3 (labled "scenarios" by OffSec) are compromised of expansive but self-contained Active Directory-based networks, each with an accompanying narrative and character. 
- Challenges 4-6 are mock exam networks, each containing a 3-machine Active Directory set and 3 standalone machines.

Of the first three challenges, I obtained domain administrator access in the first and second networks. Interestingly, I was able to do so by compromising 71% of the flags in the first network and only 41% of the second. The third challenge network is presented as being "beyond the scope" of the exam, so I chose to skip it, though I am confident that it is worth doing for students looking to maximze their PEN200 experience.

Unsurprisingly, challenges 4-6 provided the most relelvant practice and preparation for the OSCP exam. As such, I completed each of them. I found both the contents and difficulty of these boxes to closely comparable to those that I encountered on the exam.

### Exam Impressions
[Coming soon.] 


