---
layout: post
category : template
tagline: "Supporting tagline"
tags : [template]
---
{% include JB/setup %}

Syntax highlighting...

## Hello Word!

### C

This is a test!

{% highlight C linenos %}
#include<stdio.h>

main()
{
  printf("Hello World");

}
{% endhighlight %}

### Ruby

{% highlight Ruby %}
puts 'Hello world'
{% endhighlight %}

### IDA Pro

{% highlight text %}
.text:00012C7B                 call    ds:ExAllocatePoolWithTag
.text:00012C81                 mov     P, eax
.text:00012C86                 cmp     P, 0
.text:00012C8D                 jnz     short loc_12C99
.text:00012C8F                 mov     eax, 0C000009Ah
.text:00012C94                 jmp     loc_12E83
.text:00012C99 ; ---------------------------------------------------------------------------
.text:00012C99
.text:00012C99 loc_12C99:                              ; CODE XREF: sub_12C20+6Dj
.text:00012C99                 mov     ecx, 200h
.text:00012C9E                 xor     eax, eax
.text:00012CA0                 mov     edi, P
.text:00012CA6                 rep stosd
.text:00012CA8                 mov     edx, [ebp+arg_0]
.text:00012CAB                 push    edx             ; wchar_t *
.text:00012CAC                 call    ds:__imp_wcslen
.text:00012CB2                 add     esp, 4
.text:00012CB5                 push    eax             ; size_t
.text:00012CB6                 mov     eax, [ebp+arg_0]
.text:00012CB9                 push    eax             ; wchar_t *
.text:00012CBA                 mov     ecx, P
.text:00012CC0                 push    ecx             ; wchar_t *
.text:00012CC1                 call    ds:__imp_wcsncpy
{% endhighlight %}

### WinDbg
{% highlight text %}
kd> !pool eax
Pool page 86294110 region is Nonpaged pool
 86294000 size:   30 previous size:    0  (Allocated)  Even (Protected)
 86294030 size:   10 previous size:   30  (Free)       ....
 86294040 size:   30 previous size:   10  (Allocated)  Even (Protected)
 86294070 size:   30 previous size:   30  (Allocated)  Even (Protected)
 862940a0 size:   30 previous size:   30  (Allocated)  Even (Protected)
 862940d0 size:   30 previous size:   30  (Allocated)  Even (Protected)
 86294100 size:    8 previous size:   30  (Free)       Even
*86294108 size:  808 previous size:    8  (Allocated) *Qrnt		//  0x30*0x2b = 0x810
		Owning component : Unknown (update pooltag.txt)	// 0x810-0x808 = 0x8
 86294910 size:   30 previous size:  808  (Allocated)  Even (Protected)
 86294940 size:   30 previous size:   30  (Allocated)  Even (Protected)
 86294970 size:   30 previous size:   30  (Allocated)  Even (Protected)
 862949a0 size:   30 previous size:   30  (Allocated)  Even (Protected)
 862949d0 size:   30 previous size:   30  (Allocated)  Even (Protected)
 86294a00 size:   30 previous size:   30  (Allocated)  Even (Protected)
{% endhighlight %}

<!--
### Examples

This website is created with Jekyll. [Other Jekyll websites](https://github.com/mojombo/jekyll/wiki/Sites).
-->