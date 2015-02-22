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

### IDA

{% highlight IDA %}
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

<!--
### Examples

This website is created with Jekyll. [Other Jekyll websites](https://github.com/mojombo/jekyll/wiki/Sites).
-->