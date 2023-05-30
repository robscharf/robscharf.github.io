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

I am happy to share that I recently passed the the Penetration Testing with Kali Linux certification exam on May 10!

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
[Coming soon.] 

#### PEN200 2023 - Labs
[Coming soon.] 

### Exam Impressions
[Coming soon.] 


