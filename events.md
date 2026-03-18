---
layout: default
title: CTF Events
has_children: true
has_toc: false
nav_order: 1
child_nav_order: reversed
---

# CTF Events

Competition write-ups from timed CTF events.

<div class="card-grid">
{% assign children = site.html_pages | where: "parent", "CTF Events" | sort: "nav_order" | reverse %}
{% for child in children %}
<div class="card">
  <div class="card__title"><a href="{{ child.url | relative_url }}">{{ child.title }}</a></div>
  {% if child.description %}
  <div class="card__description">{{ child.description }}</div>
  {% endif %}
  <div class="card__meta">
    {% if child.date %}<span class="card__date">{{ child.date | date: "%Y" }}</span>{% endif %}
    {% assign grandchildren = site.html_pages | where: "parent", child.title | size %}
    {% if grandchildren > 0 %}<span>{{ grandchildren }} write-ups</span>{% endif %}
  </div>
</div>
{% endfor %}
</div>
