---
layout: post
title: "Z3 Solver vs. IoAllocateMdl"
description: ""
category: 
tags: [z3, ida]
---
{% include JB/setup %}

Recall..
{% highlight C %}
PMDL __stdcall IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)
{
[...]
	v6 = ((Length & 0xFFF) + ((unsigned __int16)VirtualAddress & 0xFFF) + 0xFFF) >> 12;
	v7 = v6 + (Length >> 12);

	v15 = (unsigned __int16)VirtualAddress & 0xFFF;
	if ( v7 > 0x11 )
	{
		v8 = 4 * v7 + 28;
		goto LABEL_8;
	}

[...]
 	if (!result)
	{
		v8 = 96;
LABEL_8:
		result = (PMDL)ExAllocatePoolWithTag(0, v8, 0x206C644Du);
		if (!result)
			return result;
  	}
[...]
}
{% endhighlight %}


Using z3 solver to solve 'Length' and 'VirtualAddress'..

{% highlight Python %}
#!/usr/bin/python

from z3 import *

Length = BitVec('Length', 32)
VirtualAddress = BitVec('VirtualAddress', 32)

v6 = (Length & 0xFFF) + LShR(((VirtualAddress & 0xFFF) + 0xFFF), 12)
v7 = v6 + LShR(Length, 12)
v8 = 4 * v7 + 28;

solve(v8 == 0xA0)
{% endhighlight %}

Console:
{% highlight text %}
[Length = 4127, VirtualAddress = 2]
{% endhighlight %}