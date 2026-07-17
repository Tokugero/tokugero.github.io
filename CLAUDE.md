# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Jekyll-based static blog for CTF (Capture-The-Flag) challenge writeups and cybersecurity research, hosted on GitHub Pages. Content is personal documentation of CTF solutions, primarily from HackTheBox and TryHackMe.

## Development Environment

This project uses Nix flakes + direnv for reproducible dev environments.

```bash
direnv allow                                       # first-time: activates .envrc → use flake
bundle config set --local path 'vendor/bundle'    # first-time only
bundle install                                     # first-time only
bundle exec jekyll serve                           # local dev server
bundle exec jekyll build                           # production build
```

The shell activates automatically on `cd` once `direnv allow` has been run. The dev server is available at `http://localhost:4000` by default.

## Content Architecture

Content lives in `ctf/events/<event-slug>/` as Markdown files. Each challenge writeup uses this front matter structure:

```yaml
layout: post
title: "Challenge Name"
date: YYYY-MM-DD 00:00:00 -0700
categories: challenges
description: Brief summary
parent: "Event Name"         # matches the event index page title
grand_parent: Challenges
event: "event-slug"
tags: [tag1, tag2]
published: true              # set false to draft/unpublish — see "Publishing embargo"
```

Event index pages (e.g., `ctf/events/season8-htb-25/index.md`) use `layout: page` and serve as the `parent` for individual challenge posts.

Images go in `assets/images/ctf/events/<event-slug>/` and are referenced as `/assets/images/ctf/events/<event-slug>/filename.png`.

## Theme & Navigation

The site uses [just-the-docs](https://just-the-docs.com/) v0.8.1 (dark scheme). Navigation hierarchy is driven entirely by front matter `parent`/`grand_parent` fields — there is no manual nav config. The top-level nav pages are `index.md`, `events.md`, and `challenges.md`.

## Adding New Content

1. Create a new event directory under `ctf/events/<event-slug>/` with an `index.md`
2. Add challenge writeup files named `YYYY-MM-DD-<slug>.md`
3. Set `parent` to match the event index page's `title` exactly
4. Add images to `assets/images/ctf/events/<event-slug>/`

## Publishing embargo (7-day author courtesy)

HTB/room authors generally dislike public writeups until **7 days after a
challenge's release**. The post `date:` is the day the box was **solved**, NOT the day
it was released, and the two can differ by an unknown amount — there is no release date
in the repo, so the embargo **cannot be computed**. It is decided by the operator at
writeup time and recorded in front matter.

**At writeup time** (a `Publish timing` ruling in the interview ledger), the default is
"safe to release now" → `published: true`. If the box is too fresh, the operator holds
it and gives the date it becomes safe. A held post carries:

```yaml
published: false
publish_after: 2026-07-19   # embargo lifts — safe to publish on/after this date
```

**Before any publish/commit pass, scan for held posts and release the cleared ones:**

```bash
grep -rn "published: false" ctf/events/     # find every held post + its publish_after
```

For each hit, compare `publish_after` to today: on/after that date the embargo has
lifted → flip to `published: true` in the same pass (confirm with the operator). A post
with `published: false` and no `publish_after` is undetermined — ask the operator, and
**hold when uncertain** (publishing early is a real discourtesy; holding a week is cheap
and reversible). A batch release may therefore split: publish cleared posts now, leave
still-embargoed ones held for a later pass.
