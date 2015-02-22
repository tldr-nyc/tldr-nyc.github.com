---
layout: page
title: /dev/random
tagline: Supporting tagline
---
{% include JB/setup %}

Well, that escalated quickly..

<!---"Deadlisting reverse engineering, as +ORC calls it, is a slow 'puzzle solving' process: the intellectual challenge can be extremely interesting."

## idaq.exe
-->

Oh, and this is my notepad.

<ul class="posts">
  {% for post in site.posts %}
    <li><span>{{ post.date | date_to_string }}</span> &raquo; <a href="{{ BASE_PATH }}{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>

<!--
## Happy Deadlisting!
-->

