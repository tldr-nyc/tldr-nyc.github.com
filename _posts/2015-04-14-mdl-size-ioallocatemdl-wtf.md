---
layout: post
title: "MDL Size (IoAllocateMdl)"
description: ""
category: 
tags: [ida]
---
{% include JB/setup %}

@OS: Win7x86FRE    
@arget: ntoskrnl.exe (6.1.7600.16385)     


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

https://github.com/JeremyFetiveau/Exploits/blob/master/MS14-040.cpp    
@OS: Win8x64FRE    
@Src: MS14-040.cpp    

{% highlight C %}
UINT32 vaddr = 0x13371337;
UINT32 targetSize = 0x100; // >= 0x100
UINT32 mdlsize = (pow(2.0, 0x0c) * (targetSize - 0x30) / 8) - 0xfff - (vaddr & 0xfff);
{% endhighlight %}


http://www.secniu.com/cve-2014-1767-afd-sys-double-free-vulnerability-analysis-and-exploit/    
@OS: Win7x86FRE    
@Src: afd_1767_win32_Exp.cpp    

{% highlight C %}
// 0xA0 == WorkFactory Allocated Object Size
const DWORD FakeObjSize = 0xA0 ;
DWORD mdlSize = FakeObjSize ;
DWORD virtualAddress = 0x710DDDD ;
DWORD length = ((mdlSize - 0x1C)/4 - (virtualAddress%4 ? 1:0))*0x1000 ;
{% endhighlight %}

Basically..

{% highlight C %}
mdlsize = v8 // (PMDL)ExAllocatePoolWithTag(0, v8, 0x206C644Du)
v8 = 4 * v7 + 28
v8 = 4 * v7 + 0x1C
{% endhighlight %}

This means:

{% highlight C %}
v7 = (mdlsize - 0x1c)/4

v7 = v6 + (Length >> 12);
v7 = v6 + (Length/(2^0xc))

v6 = ((Length & 0xFFF) + (VirtualAddress & 0xFFF) + 0xFFF) >> 12;
v6 = ((Length & 0xFFF) + (VirtualAddress & 0xFFF) + 0xFFF) /(2^0xc);

v7 = ((Length & 0xFFF) + (VirtualAddress & 0xFFF) + 0xFFF) /(2^0xc) + (Length/(2^0xc))


v7 * (2^0xc) = (Length & 0xFFF) + (VirtualAddress & 0xFFF) + 0xFFF) + Length
(v7 * (2^0xc)) - 0xfff - (VirtualAddress & 0xFFF) = (Length & 0xFFF) + Length
{% endhighlight %}

WTF?

