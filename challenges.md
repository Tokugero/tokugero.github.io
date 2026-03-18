---
layout: default
title: Challenges
has_children: true
has_toc: false
nav_order: 2
child_nav_order: reversed
---

# Challenges

Standalone machine and challenge write-ups from ongoing platform seasons.

<div class="card-grid">
{% assign children = site.html_pages | where: "parent", "Challenges" | sort: "nav_order" | reverse %}
{% for child in children %}
<div class="card">
  <div class="card__title"><a href="{{ child.url | relative_url }}">{{ child.title }}</a></div>
  {% if child.description %}
  <div class="card__description">{{ child.description }}</div>
  {% endif %}
  <div class="card__meta">
    {% assign grandchildren = site.html_pages | where: "parent", child.title | size %}
    {% if grandchildren > 0 %}<span>{{ grandchildren }} write-ups</span>{% endif %}
  </div>
</div>
{% endfor %}
</div>

---

This is the first set of events I am applying some note taking strategies I learned while at LayerOne '24. Between Jupyter notebooks and GitHub CoPilot, the experience quickly became natural outside of the effort of screen capturing or GUI tools like BurpSuite/ZAProxy.
