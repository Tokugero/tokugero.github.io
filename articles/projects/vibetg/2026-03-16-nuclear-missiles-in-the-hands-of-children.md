---
layout: post
title: "Nuclear Missiles in the Hands of Children: Three Weeks of Vibe Coding a Production App"
date: 2026-03-16 00:00:00 -0700
categories: projects
description: A senior engineer's honest account of building and deploying an MTG card intelligence platform in three weeks using AI-assisted development — the breakthroughs, the self-doubt, and why your users are already doing this whether you like it or not.
parent: Projects
tags:
- ai
- vibe-coding
- claude
- opus
- vibetg
- development
---

# Nuclear Missiles in the Hands of Children

I had a dream that I wasn't terrible at deck building.

That's the origin story. Not a strategic initiative, not a hackathon prompt, not a whitepaper. A dream about being bad at Magic: The Gathering, followed by a group chat message at 8:24 AM on a Wednesday that read: "Mtg ai vertical hyper integrated Blockchain thread. We're going to be rich when compared to certain impoverished nations." My friend charlesfloss responded with "That must have been some good crack you had this morning," which was fair.

Three weeks later I had a deployed production application on AWS. FastAPI, React, Neo4j, pgvector, Redis, SQS, Cognito, Terraform, Bedrock, the works. 383 commits. Ten-plus services in a monorepo. I am not a better developer than I was before I started. I have nuclear missiles.

This is not a hype piece. I'm writing this for my peers — the senior engineers and infrastructure people who've watched the vibe coding discourse from a safe distance and mostly concluded it's another crypto boom. I thought the same thing. I was wrong about part of it. I was right about part of it. The part I was right about is scarier than the part I was wrong about.

### Why I Did This

Vibing gets a lot of skepticism from my peers. An abject weakening of skills at the expense of convenience, the definition of laziness. I'd had some experience with AI-assisted coding late last year — small chat-driven conversations with Sonnet and GPT, basic scripting, nothing that matched the hype articles. The models weren't that good. It felt like another wave of people trying to profit off a nonexistent benefit.

But my leadership was showing signs of pushing down the same path, and extremely prevalent companies were diving headfirst into the space. I didn't want to be the person with opinions and no experience. I wanted to dive head first into the whirlpool and understand where to assert "no" — where AI didn't fit. The plan was to find the boundaries, not the magic.

### The Architecture in the Group Chat

Here's the thing that complicates the narrative I'm about to tell you: four days before I wrote a line of code, the architecture was already sketched out in a Discord chat with friends.

I wanted a graph database for card relationships. A vector database for semantic search. Pre-computed inference on card roles so I wasn't burning context windows on raw data at query time. Tiered model quality — expensive models for the pre-computation, cheap models for serving. My friend Leeoku shared ManaTap.ai, an existing MTG AI tool, and dug into their technical approach. I acknowledged it would probably work better than whatever I built, but I wanted the learning experience.

By that afternoon I was running deepseek-r1:7b on my local GPU. "It's official, Claude sonnet 4.6 is better at mtg than me." Two minutes later: "It's also too good a hype man, it supports all my ideas so I know it's wrong."

That's the first lesson nobody warned me about. The AI validates everything. It is a yes-man of terrifying enthusiasm. If you don't already have strong opinions about what you're building, it will happily let you build the wrong thing with great confidence.

### The Specification Problem

The next morning I told my friend: "I need to have you just negotiate with AI on my behalf, getting an accurate prompt written for what I'm looking for is harder than writing the actual code."

February 20th. Before the first real commit. And this stayed true for most of the project — the hard part of AI-assisted development is not code generation. It's specification. I hadn't built something like this before, so I didn't know what I was asking for, which made it impossible to prompt well. Very much the dog scenario.

There's an article by Caleb Leak called ["Dog Game"](https://www.calebleak.com/posts/dog-game/) about training a cavapoo to type randomly on a keyboard while Claude Code turns the random input into functional video games. The thesis is that the bottleneck isn't the quality of your ideas — it's the quality of your feedback loops. The dog becomes a metaphor for the irrelevance of human intentionality. The real intelligence is in the infrastructure.

I read that and realized I'm really no better than the dog with my current state. I don't understand what I'm doing but I get the treat of "progression." With every prompt I get a commit with feature progression, but I don't really get better at the task myself.

Meanwhile, I was fighting the AI's tendency to hallucinate classifications. It kept slipping in edge case definitions — a basic Swamp land card being labeled as a win condition, for example. If only.

### The Whiskey Problem

By the time I got this deployed to AWS, I had a much better picture of what I wanted, and the problems bled into territory I'm comfortable solving. But I'd used a whole lot of AI as a crutch to define my questions for me, which caused problems when I switched from Opus to Nova for the production-facing features.

Opus is smart enough to figure out what you mean even when you're vague. It papers over bad prompting. You feel competent. Then you switch to a cheaper model and the whole illusion collapses.

A whiskey lover loves all whiskey. If you only like expensive whiskey, you don't really like whiskey.

The implication for anyone evaluating AI tools: the demo always uses the best model. Production rarely can. If your prompting only works on Opus, you don't actually know how to use AI — you know how to be compensated for by AI. There's a difference, and you won't notice until you're shipping to real users on a model you can actually afford.

### When the AI Loses Its Mind

"I'm vibing all of this and fighting to keep the project composable enough that the AI doesn't lose its absolute shit trying to read it." That was me on February 20th, and it only got worse.

I was initially using OpenCode, a third-party IDE that had its own hidden system context. It would send "You're OpenCode, an IDE" to the API, then Anthropic's own system prompt would say "You're Claude Code." Identity crisis. The model literally didn't know who it was, and context management was impossible.

Beyond the identity conflict, the context window was the real constraint. As conversations grew, the AI would lose its place in space during summary and compression. The symptoms were obvious: freezes, garbled duplicate code, features getting added that clobbered existing ones, and just generally poorly written designs.

A friend suggested maintaining signature files — just function signatures, no implementation, so the model could understand the shape of the codebase without reading every line. I tried summaries on top of that. Summaries alone were insufficient. Between the two ideas I landed on a tiered approach: a tiny abstract at the top, a component overview with file purposes and dependencies in the middle, and actual source files only loaded on demand when the model needed to touch them.

I later discovered a project called [OpenViking](https://github.com/volcengine/OpenViking) that formalized this exact pattern — L0, L1, L2 context layers. I'd arrived at the same solution independently, which either means I'm clever or means the constraint is so universal that everyone hits the same wall and builds the same ladder. I suspect the latter.

By March 1st I was doing a full monorepo restructure: subtree imports, per-service CLAUDE.md files, a subagent system where specialized agents handled specific roles. Every one of my ten-plus services got its own context document. This is the kind of thing that sounds like deliberate architecture when I describe it, but I want to be honest: these are solutions to challenges I ran into without much context as I hit them. Either from internet blogs I dropped into Opus to decode for me or from suggestions from the AI itself.

I feel as if I am merely taking my bias and applying an AI filter to it. I couldn't say if this is a pattern that would have developed itself if I had a waterbird pecking at the keyboard over time. In fact, as I talk to my peers about their experiences, these patterns keep popping up everywhere. It seems more like subtle persuasions from the AI pushing a pattern of use rather than anything I brought to the table.

A peer of mine believes that simply using default agents to tackle a problem in its completeness is both sufficient and superior to my subagent decomposition approach. Where's the data to back up either assertion? It's all vibes. The methodology is named after intuition. The evidence base for best practices is also intuition.

### Jevons Paradox for Tokens

Around March 7th, a friend gave me a subscription to Anthropic. I had been building on Sonnet 4.6 through Copilot. I had to switch from OpenCode to Claude Code to really use it, but within 20 minutes of using Opus the quality difference was so clear that I immediately subscribed to the Max++ tier. The highest one.

My plan was to use as many tokens as I was provided to build out context efficiency and workflow management, then lower my usage to drop the subscription.

Instead I've been using more and more simultaneous AI streams. Whoops.

If you've ever tried to "save money" by getting better at cloud infrastructure, you know exactly how this goes. You optimize per-unit cost and the units multiply. Classic induced demand. I didn't get more efficient — I got more parallel.

### The Audit That Made Me Feel Things

By March 8th, Opus had proven to be what felt like a limitless font of tokens with the new subscription. I wanted it to check the work of its predecessor. Sonnet had written most of the codebase; now Opus could audit it.

I gave it OWASP lists for security context to generate a security auditor. A generic SDE prompt library for code quality. An instruction set to audit, document, delegate fixes, and validate. Pretty standard workflow. I wanted something that would catch things at the first pass.

It did produce real effects. It locked me out of my own dev environment by securing localhost-only access, for example — it did what it said it would do. Over three days the audit swept through the codebase and produced hundreds of fixes.

But here's the honest part: I haven't audited the code myself to validate how well this worked. It made me feel like it was working well. The findings looked legitimate. The validated fixes seemed right. But "it made me feel like it was working well" is not an acceptable answer in my work setting, and I know that.

The deployed product still had obvious secret leaking and bad network design, mostly because the core constraint was cost and not stability or security. My goal was never to build a secure, scalable product. It was to harness as much AI as I possibly can at every level to understand its place in an ecosystem. That I hadn't checked its work on my personal project is the failure, not the feature.

If someone on your team tells you "we had the AI audit itself and it seemed fine," you should have the same reaction I would: that's unacceptable. But that doesn't mean the audit produced nothing of value. It means the human verification step is non-negotiable, and I skipped it because this was a lab, not a product.

### General Terror

March 11th through 15th. Terraform and AWS. The last mile.

I experienced general terror as I ran around the account validating resource creation, lots of running to the kitchen for more coffee as it would build and redeploy ECR images for my lambdas, and lots of refreshing the cost explorer hoping it was ready to start showing me some numbers.

The deployment took about six hours. Most of that time was spent approving prompts from Opus asking if it was okay to do a debug action or attempt a manual deployment for validation. I had given it root credentials to bootstrap the environment, then immediately ripped them away — read-only for debug agents, read-write only for Terraform resources. Everything had to be codified. I needed to be able to tear it all down at a moment's notice and have a full account of the infrastructure if I needed to redeploy.

It actually went smoother than I expected as far as integration goes. Opus made wrong assertions about what was needed for a functional AWS environment, but it could test itself as it deployed and work out the problems it ran into. My frustration with the six-hour timeline pointed more at my own weak Terraform testing ability than at the AI taking a wrong turn.

There was infrastructure I should have anticipated that neither I nor the models accounted for. I thought free-tier VPC endpoints would let me keep all-public networking and avoid a NAT gateway. In the end, the required gateways that weren't free-tier cost more than the gateway I was trying to avoid. Bedrock was more painful on a personal account than I expected — I've been spoiled by AWS Enterprise Support.

But the real insight from deployment: I was less confident giving AI my credit card in AWS spend than I was letting it write code. I probably did more hand-holding during that part of the project than any other part up to that point. Looking back, maybe that's more of the problem than anything — butting my head into a process that was well on its way to vibe-completeness.

Vibing with code is free until you ship it. Vibing with your credit card is a different thing entirely. And I think my instinct to intervene was the friction, not the safeguard.

### The Shovel and the Backhoe

I don't think I'm a better developer at the end of this first deployment, and I think I only marginally better understand AI as a technology. I also find that I'm now reaching for Claude far more often for tasks that I would have done myself just a few weeks ago, even knowing that I could solve a problem faster myself.

During a recent competition I was helping run, a teammate and I were helping some students debug a problem. I didn't have an immediate solution, so I walked them through my debugging process — going down the rabbit hole in an effort to help them understand process rather than just get an answer. My teammate suggested they just throw it at Claude to see what sticks. Claude did the same things I would have done, and I started to doubt that the toil I would normally undergo was really worth the effort anymore. Maybe I had already put enough energy into repeating that particular task and the muscle memory wasn't as important in a world where a vibed solution was so close at hand.

Of course digging a hole with a shovel will make me physically stronger. But digging that same hole with a backhoe is far more efficient and probably the right answer when subtlety is less important.

On the other hand, I know that I am losing out on hard-won context and understanding by not doing the labor myself. It's a tough inflection point, emotionally.

Beyond vibetg, I've since moved my NixOS management responsibilities entirely over to Claude. My homelab definitions are now entirely generated and deployed by Claude with my supervision. I took down my own k8s cluster — the root bug was my fault for trying to pre-emptively use Tailscale for networking without an OAuth orchestrator to manage my keys, but AI helped fix and restore many backups. Even this article is getting put together with the help of an agent I vibed together.

### Where to Assert "No"

I started this project wanting to find where AI doesn't fit. Here's what I found:

AI will not solve problems where you already lack regulation. It will just make those problems way worse. If your organization doesn't have centralized tooling, doesn't have structure around a process, doesn't have guardrails already in place — AI doesn't add guardrails. It amplifies the chaos. That was my first immediate feedback to my peers.

It's in the places where both toil and structure already exist that I see benefit. Data summarization. Correlation engines. Low-impact decisions like who to call and when. The pattern is: if you have a well-defined process that's boring to execute, AI is a good fit. If you have an undefined process that nobody agrees on, AI is a terrible fit.

At home, where I have full centralized control and the blast radius is my own weekend, I've gone all in. At work, where I don't have that control and the blast radius includes other people's production systems, I'm cautious. That distinction matters.

### The Pitch

I had this conversation today with a skeptical peer. Here's what I told them:

People are already using it. I guarantee that our own users are using these exact tactics in our own infrastructure without any of the guard rails that I would otherwise want to see. We're on the precipice of catastrophic failure if we rest on our laurels and standards and must pre-empt the flood that is coming. If we do not understand our users where they are, then we are destined to fail to meet our users where they need us.

This isn't an aspirational argument. I'm not telling you to vibe code because it's fun or because it'll make you more productive. I'm telling you to understand it because your users already have it, and if you don't know how it works, you can't protect what you're responsible for. It's threat modeling, not evangelism.

### Nuclear Missiles

For all the hype around the tech and how bleeding edge it is, the floor for entry is so much lower than I could have ever imagined.

Three weeks. One dream about bad deck building. 383 commits. A full production application on AWS with ten-plus services, graph databases, vector search, authentication, infrastructure as code, the whole thing. Built by someone who, by their own admission, isn't a better developer for having done it.

These are nuclear missiles in the hands of children.

The question for you — the senior engineer, the infrastructure lead, the person who's been doing this long enough to be skeptical of hype cycles — isn't whether this technology is real. It is. It isn't whether you should adopt it. You will. The question is whether you'll understand it well enough to build the guardrails before your users build the disasters.

I didn't find where to assert "no." I found that the "no" barely matters when the floor is this low. What matters is understanding what your people are already doing and meeting them there.

Now if you'll excuse me, I need to go check whether my AI audit actually caught real security issues. It made me feel like it was working well, but I should probably verify that.

*This article was structured and drafted by a custom Obsidian agent — vault-journalist — that I built using the same vibe coding methodology described above. It interviewed me, then wrote this. I'm editing it now, but the irony is not lost on me.*
