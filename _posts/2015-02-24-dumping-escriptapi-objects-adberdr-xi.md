---
layout: post
title: "Dumping EScript.api Objects (AdbeRdr XI)"
description: ""
category: 
tags: []
---
{% include JB/setup %}

## Using IDAPython to dump all objects in EScript.api (Adobe JavaScript Engine)

### acrord_obj.py

{% highlight Python %}
from idaapi import *

# Reference: http://www.immunityinc.com/downloads/ID_reCON_2008.odp

# addr = get_screen_ea()
addr = 0x23975878
for x in range(0, 207):
    offset = 0
    
    print "[Object %d] Address: 0x%08x" % (x, addr)
    # Object Name [ptr to "App"]
    ptrObjectName = Dword(addr)
    ObjectName = GetString(ptrObjectName, -1, ASCSTR_C)
    print "Offset +0x%02x Object \"%s\"" % (offset, ObjectName)
    addr += 4
    offset += 4
    
    # Unknown [0x0]
    print "Offset +0x%02x ???" % offset
    addr += 4
    offset += 4
    
    # Members [ptr to 5C Members Structures]
    ptrMembers = Dword(addr)
    print "Offset +0x%02x ptrMembers 0x%08x" % (offset, ptrMembers)
    addr += 4
    offset += 4
    
    # Members counter [0x5c]
    counterMembers = Dword(addr)
    print "Offset +0x%02x counterMembers = 0x%x\n" % (offset, counterMembers)
    addr += 4
    offset += 4
{% endhighlight %}

### Console
{% highlight text %}
[Object 0] Address: 0x23975878
Offset +0x00 Object "App"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x23949cd8
Offset +0x0c counterMembers = 0x5c

[Object 1] Address: 0x23975888
Offset +0x00 Object "AppMedia"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b1e8
Offset +0x0c counterMembers = 0x28

[Object 2] Address: 0x23975898
Offset +0x00 Object "AppMediaPriv"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b6e8
Offset +0x0c counterMembers = 0x1

[Object 3] Address: 0x239758a8
Offset +0x00 Object "Array"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b708
Offset +0x0c counterMembers = 0x11

[Object 4] Address: 0x239758b8
Offset +0x00 Object "AttributeName"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b928
Offset +0x0c counterMembers = 0x1

[Object 5] Address: 0x239758c8
Offset +0x00 Object "bookletBindings"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b948
Offset +0x0c counterMembers = 0x4

[Object 6] Address: 0x239758d8
Offset +0x00 Object "bookletDuplexModes"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394b9c8
Offset +0x0c counterMembers = 0x3

[Object 7] Address: 0x239758e8
Offset +0x00 Object "Bookmark"
Offset +0x04 ???
Offset +0x08 ptrMembers 0x2394bd00
Offset +0x0c counterMembers = 0xe

...

{% endhighlight %}