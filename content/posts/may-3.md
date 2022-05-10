+++
title = "How to add a backtick hotkey to Windows 10"
description = "Installing AutoHotkey to add custom key mapping in Windows 10"
type = ["posts","post"]
tags = [
    "blog",
    "autohotkey",
    "backtick",
    "markdown",
    "obsidian"
]
date = "2022-05-10T13:00:00"
showthedate = false
categories = [
    "Windows",
    "Obsidian",
]
[ author ]
  name = "Rob"
+++

Lately I have been really enjoying [Obsidian](https://obsidian.md/) as a personal knowledge base. It uses simple `Markdown` files, which makes maintaining synchronized cross-platform access easy and low impact. 

### The problem

I recently ran into a small problem when I decided to change my workflow to run Obsidian on my Windows PC host machine, instead of inside my Kali or Ubuntu virtual machines. Until now, I have largely been running Obsidian on my Macbook and inside my working machines on my PC. However, when I went to start my first `.md` in Windows, I quickly realized that my 65% keyboard lacks a `` ` `` / `~` key. Not being able to type backticks, and thus write `code` blocks, would make my markdown adventures a lot less convenient.

### The Solution

Adding a hotkey mapping in Windows 10 is surprisngly easy, thanks to [AutoHotkey](https://www.autohotkey.com/). The AutoHotkey software is fully open-source and [maintained by a non-profit foundation](https://autohotkey.com/foundation/history.html). 

To add a backtick hotkey, simply create an `.ahk` file and fill it with the following line: 
```
^'::Send ```
```
**Note:** three `` ``` `` characters are needed, as the backtick ( `` ` `` ) is the primary escape character in AutoHotkey scripts. 

You now have an executable AutoHotkey script. If you place this file in the `C:\Users\<your-username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` directory, it will execute whenever Windows is started. 
