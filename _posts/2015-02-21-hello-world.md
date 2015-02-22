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

{% highlight C %}
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

{% highlight ASM %}
.text:00000000004004D0 main proc near
.text:00000000004004D0 48 83 EC 08 sub rsp, 8
.text:00000000004004D4 BF E8 05 40 00 mov edi, offset format ; "hello, world\n"
.text:00000000004004D9 31 C0 xor eax, eax
.text:00000000004004DB E8 D8 FE FF FF call _printf
.text:00000000004004E0 31 C0 xor eax, eax
.text:00000000004004E2 48 83 C4 08 add rsp, 8
.text:00000000004004E6 C3 retn
.text:00000000004004E6 main endp
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