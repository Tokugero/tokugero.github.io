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
published: true              # set false to draft/unpublish
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
