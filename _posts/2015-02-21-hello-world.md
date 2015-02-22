---
layout: post
category : exploit
tagline: "Supporting tagline"
tags : [hello, world]
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
{% highlight ASM %}
(4f0.d48): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=03904a18 ecx=001f0044 edx=00000000 esi=020be380 edi=00000000
eip=6363fcc6 esp=020be354 ebp=020be36c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!CElement::Doc+0x2:
6363fcc6 8b5070          mov     edx,dword ptr [eax+70h] ds:0023:00000070=????????

0:008> u mshtml!CElement::Doc
mshtml!CElement::Doc:
6363fcc4 8b01            mov     eax,dword ptr [ecx]
6363fcc6 8b5070          mov     edx,dword ptr [eax+70h]
6363fcc9 ffd2            call    edx
{% endhighlight %}

<!--
### Examples

This website is created with Jekyll. [Other Jekyll websites](https://github.com/mojombo/jekyll/wiki/Sites).
-->