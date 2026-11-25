# Distribution posts

Repo: https://github.com/NishantDixit1/launch-check
Hosted: https://stackwrights.com/tools/launch-check

---

## 1. Hacker News (Show HN)

**Title** (80 char limit, no emoji, no hype, HN hates both)

```
Show HN: Launch-check – find out if your deployed app is leaking database rows
```

**URL:** https://github.com/NishantDixit1/launch-check

**First comment, post it immediately after submitting:**

```
We run a small studio and kept being handed apps built in a weekend with
Lovable or Bolt, already live, already with real customers in them. The same
four things were wrong almost every time, and none of them is visible from
using the app.

The big one: Supabase exposes your database to the browser by design, which is
fine as long as every table has a row level security policy. Generated apps
routinely have tables with no policy, or a policy covering SELECT but not
UPDATE, or one written for the first table and never added to the other six.
The app works perfectly either way, because your own app sends the right
queries. Someone else can send different ones.

So the check is literally: ask the database for one row, without logging in,
and see if it answers.

It also reads the JS bundle for keys that should have stayed server-side,
requests /.env the way anyone could, checks for public source maps, and looks
at security headers.

Everything is read-only and already public. It asks for one row per table, never
prints row contents, redacts secrets to first and last characters, and there is
no server, it all runs in your terminal. Zero dependencies, Node 18+.

The part I actually think is the useful bit: each finding comes with a prompt
written for the assistant that built the app. Knowing RLS is off does not help
if you do not know what RLS is, so `--fix` gives you something to paste into
Claude Code or Cursor.

  npx launch-check https://yourapp.com --fix

Exit codes are set up for CI (2 on a critical or high), which is where I would
actually want this.

Gaps I know about: Firebase rules are not checked yet, and the secret pattern
list is deliberately conservative because a false positive on a security report
costs more than a miss. PRs very welcome on both.
```

**Timing:** Tuesday to Thursday, 08:00 to 10:00 ET. Do not ask anyone to upvote, HN detects voting rings and it will bury the post.

---

## 2. r/SaaS and r/indiehackers

**Title**

```
I built a free CLI that tells you if your Supabase tables are publicly readable
```

**Body**

```
Short version: `npx launch-check https://yourapp.com`

Background. I run a small dev studio and we keep getting asked to look at apps
built quickly in Lovable, Bolt or Replit that are already live with real users.
The same problem shows up over and over: the database answers anonymous
requests.

Supabase puts your database in front of the browser on purpose. That is the
design and it is fine, as long as every table has a row level security policy.
What happens in practice is that some tables have one, some do not, and some
have a policy covering reads but not updates. Your app works perfectly either
way, because your app sends the correct queries. Anyone else can send
different ones.

You can check this yourself in one minute: open your app signed out, open the
browser console, and ask your database for a row from a table you think is
private. If it answers, that table is public.

I got tired of doing that by hand, so this does it, plus a few other things:

- Reads the JS your visitors download, looking for API keys that should have
  stayed on the server
- Requests /.env and /.git/config the way a stranger could
- Checks for public source maps
- Checks security headers

Read-only throughout. One row per table, row contents never printed, secrets
redacted, no server, nothing stored. It is all information that is already
public, which is rather the point.

Each finding comes with a prompt you can paste into whatever built the app, so
you get the fix and not just the bad news.

MIT, zero dependencies: https://github.com/NishantDixit1/launch-check

Happy to add checks if you tell me what you keep getting bitten by. Firebase
rules are the obvious gap.
```

**Rules:** r/SaaS allows this in most slots but read the sidebar on the day. Reply to every comment for the first two hours, that is what decides whether it gets seen.

---

## 3. r/Supabase

Narrower and more technical. This audience knows the subject, so no explaining what RLS is.

**Title**

```
CLI that probes your project for tables that answer anon requests
```

**Body**

```
npx launch-check https://yourapp.com

Pulls the anon key out of your published bundle (it is a JWT with role=anon, so
it is identifiable), reads /rest/v1/ for the table list, then requests one row
from each with limit=1 and reports which ones return 200 with a body.

Column names only in the output. Row contents are never printed or sent
anywhere, and there is no server, it runs locally.

It also checks whether a service_role token has ended up in the bundle, which is
the worse version of the same problem and more common than you would hope.

Caps at 25 tables per scan to keep it quick. MIT:
https://github.com/NishantDixit1/launch-check
```

---

## 4. Dev.to and Hashnode

Cross-post an existing blog post with a canonical tag back to stackwrights.com,
then mention the tool in context rather than leading with it. The canonical tag
is what stops it competing with your own page in search.

**Dev.to front matter**

```
---
title: The four things that are wrong with almost every AI-built app
published: true
tags: security, supabase, webdev, beginners
canonical_url: https://stackwrights.com/blog/lovable-app-production-ready-checklist
---
```

**Best candidates to cross-post:**

- lovable-app-production-ready-checklist
- supabase-row-level-security-guide
- multi-tenant-saas-data-isolation

Space them a week apart. Dev.to down-ranks accounts that dump five posts in a day.

---

## 5. Product Hunt

Lowest priority. PH rewards polished consumer products, and a CLI will not do
numbers there. If you launch it, launch the hosted version at
stackwrights.com/tools/launch-check rather than the npm package, and do it on a
Tuesday.

---

## Order and timing

1. **Show HN first.** Biggest upside and the only one that can produce hundreds
   of links on its own.
2. **r/Supabase the same day**, different audience, no overlap.
3. **r/SaaS two days later.** Mention it got some traction on HN if it did.
4. **Dev.to cross-posts**, one a week after that.

## Two things not to do

- Do not ask anyone to upvote. HN and Reddit both detect it and both punish it
  harder than a post that quietly does nothing.
- Do not lead with the studio. The tool is the thing being shared. The link back
  to stackwrights.com is in the README and that is enough, and the whole point is
  that the tool earns the link rather than asking for it.
