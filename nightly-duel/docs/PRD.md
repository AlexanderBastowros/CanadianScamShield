# PRD: NBA Nightly Duel

Sep 28, 2026 · @Alex

## Overview

Nightly Duel is a free, two-minute head-to-head game: you and an opponent each draft three players from tonight's NBA slate, and the better combined stat line wins.

Fantasy takes a season and a league admin. Daily fantasy costs money and is regulated. Pick'em is a solo game. Nothing gives two friends a short, fair contest built around the games on TV tonight.

**Who it is for:** NBA fans who watch with friends, and stat-minded players who want a ranked ladder.

**Goals**

- A first duel starts within 60 seconds of opening the app
- A draft finishes in under 3 minutes
- Every duel resolves the night it starts, with a shareable result
- Ranked play gives players a reason to open the app on nights when no friend is around

**Non-goals at launch**

- Real money, entry fees, prizes, or sportsbook lines
- Season-long leagues
- Team logos, player photos, or game clips, until licensing is settled

## Core duel loop

A duel is one night, one slate, six picks, and one winner. These are the launch rules for both friend duels and ranked.

**Eligibility.** A challenge can be sent only while at least one game on tonight's slate has not tipped off. "Tonight" is the NBA schedule date in US Eastern time. Challenges close 10 minutes before the night's final tip-off.

1. **Challenge.** Send a link to a friend. A coin flip decides who drafts first, and the result shows on screen. The challenger can also turn on Live Calls or switch the Coin to Veto, and the friend sees both before accepting.
2. **Draft.** Players alternate picks until each has three, with a 45 second clock per pick. A missed pick auto-selects the best available player by season average. The second seat holds the Coin (see below).
3. **Play.** Every drafted player's game counts. Scores update live as the games run.
4. **Resolve.** When the last drafted player's game ends, the higher Duel Score wins. Both players get a result card, a head-to-head record, and a rematch button.

&#91;embedded content: duel lifecycle · 4 states, 2 exits\]

A challenge not accepted by the cutoff expires. An accepted one runs to a final result, and the next game night offers a rematch.

**Player pool.** The top 10 players per team by minutes per game, from games that have not tipped off. A drafted player leaves the pool. A one-game slate gives a pool of about 20.

**Duel Score.** Points + rebounds + assists across your three players, plus bonus points from Calls and Live Calls when those are on (see below). A tie goes to the higher combined points. If that is level too, the duel is a draw.

**Inactive players.** A drafted player who is ruled out before tip-off is replaced by a free re-pick from the remaining pool. A player who is active but does not play scores 0.

## The Coin: second-seat advantage

Seat 2 gets one Coin per duel, a one-time tempo boost that offsets seat 1's first pick. The launch version is Double Pick: spend the Coin on any of your turns to make two picks in a row.

With plain alternation, seat 1 takes picks 1, 3 and 5, and seat 2 takes 2, 4 and 6. If seat 2 spends the Coin on its first turn, seat 1 takes 1, 4 and 6, and seat 2 takes 2, 3 and 5. Seat 2 ends slightly ahead on pick rank (2 + 3 + 5 against 1 + 4 + 6), and choosing when to spend the Coin is the skill.

**Veto option.** Veto is a game option the challenger can pick when sending the duel, and the friend sees it before accepting. With Veto on, seat 2's Coin becomes a Veto instead of a Double Pick: remove one player from the pool before seat 1's first pick. Ranked always uses Double Pick.

| Option | What seat 2 gets | Why consider it | Watch out for |
| --- | --- | --- | --- |
| Double Pick (launch) | Two picks in a row, once | Simple, and it mirrors a snake draft | Timing changes how strong it is |
| Veto (game option) | Remove one player from the pool before seat 1 picks | Answers the first pick directly | Can feel negative to seat 1 |

**Balance target.** Seat 2 should win 48 to 52 percent of completed duels. If it wins more, shrink the Coin. If it wins less, grow it. An unused Coin expires when the draft ends. Track the win rate separately for Double Pick and Veto.

## Side challenges: Calls

Side challenges are called Calls, and multi-leg Calls are Combos. The words avoid betting language in the UI, and "make the call" comes naturally to a sports fan. Side Quests and Hot Takes are alternatives worth testing. Calls ship in Phase 3. The in-game version, Live Calls, ships in Phase 1 and has its own section below.

- Before a player's game tips, either duelist can lock a Call on any player in that game: over or under a stat line.
- The app sets each line from that player's last 10 games (the median, rounded to the nearest half). No sportsbook lines.
- Each duelist has 3 legs per duel. A leg is a single Call, or 2 or 3 legs can be grouped into a Combo.
- Calls stay private until the game tips, then both duelists see them.
- Callable stats: points, rebounds, assists, threes made, and points + rebounds + assists.

| Call | Legs | Bonus if every leg hits | Bonus if any leg misses |
| --- | --- | --- | --- |
| Single | 1 | +2 | 0 |
| Double Combo | 2 | +6 | 0 |
| Triple Combo | 3 | +12 | 0 |

Bonus points add to the Duel Score and are capped at 12 per duel. Singles are the safe grind. Combos are the comeback button: at a 50 percent hit rate, a double lands 1 time in 4.

**Legal.** No cash entry, prizes, or purchasable legs. Legal review is needed before launch, covering Ontario and federal rules and app store policies.

## Live Calls: head-to-head during games

Live Calls is an optional Phase 1 mode where both duelists answer the same yes/no prompt about the game in front of them, and the app writes each prompt from live data as the game happens.

**How it plays**

- The challenger turns Live Calls on when sending the duel, and the friend sees that before accepting. It is off by default.
- During games, both duelists get the same prompt, such as "Will Jokic get 2 more rebounds this quarter?" Each has 20 seconds to answer Yes or No.
- A prompt moves the score only when the answers differ: whoever is right gets 2 points. No answer counts as wrong.
- Points add to the Duel Score, and the net swing is capped at 10 per duel, so drafting still decides most duels.
- Limits: one open prompt at a time, at least 4 minutes of game time between prompts, and at most 8 per duel.
- At least half of prompts target one of the six drafted players. The rest target other players on the court in live games.

| Prompt type | Example | Window ends |
| --- | --- | --- |
| Stat this period | "Will Jokic get 2 more rebounds this quarter?" | End of the period |
| Score before a stoppage | "Will Tatum hit a three before the next timeout?" | Next timeout or end of the period |
| Team run | "Will Denver outscore its opponent over the next 4 minutes of game time?" | Game clock passes the mark |
| Fouls | "Will Embiid pick up another foul this quarter?" | End of the period |

**Setting the line.** The app picks each number so Yes is close to a coin flip. It blends the player's season rate with tonight's rate, scales that to the time left in the window, and picks the number where a Poisson estimate is closest to 50 percent. Test this on historical play-by-play before launch, and aim for each prompt type to resolve Yes 45 to 55 percent of the time.

**How the engine builds a call**

1. **Watch.** The poller reads live play-by-play and box scores for every game that has a drafted player from a Live Calls duel. Polling scales with games per night, not with users.
2. **Trigger.** A prompt can open only at a dead-ball moment in the feed, such as a timeout, the end of a period, or halftime. The duel must have no open prompt, its cooldown met, and the cap not reached.
3. **Build.** Pick a prompt type and a player who is on the court, compute the line, and store a baseline: the latest play-by-play action number and the player's current stat.
4. **Deliver.** Push the prompt to both phones with a 20 second countdown. Answers are time-stamped on the server, and the prompt locks when the countdown ends.
5. **Resolve.** When the window ends, count only events after the baseline action number, score the call, and update the duel. Keep the prompt, the answers, and the events used so any result can be replayed.

nba\_api's live play-by-play endpoint returns each event with an action number, period, game clock, action type, and player ([live play-by-play source](https://github.com/swar/nba_api/blob/master/src/nba_api/live/nba/endpoints/playbyplay.py)), which is what the baseline and resolve steps need. A short spike should confirm how far the feed trails the broadcast and whether it flags who is on the court.

**Rules that keep it fair**

- Prompts open only in dead-ball moments, because feed delay differs across TV, streams, and the data source.
- If the feed has no fresh data for 30 seconds, or a game is suspended, open prompts are voided and score nothing.
- Calls resolve on live data at the window's close. Later stat corrections never reopen a call.
- A player on the bench is never chosen as the subject when a prompt opens.
- In-play prompts during live action, such as "Will the next shot go in?", are a later extension once feed delay is measured.

## In-game engagement

The best in-game features are cheap to build and make the score feel alive, so a win probability bar and chirps ship at launch, along with the optional Live Calls mode. The rest add things to do, or things to share, once the base game works.

| Idea | What the user does | Moves the score? | Phase |
| --- | --- | --- | --- |
| Win probability bar | Watches a live bar of who is ahead and gets swing alerts like "You just took the lead" | No | Launch |
| Chirps | Sends a preset taunt or reaction, offered at moments such as an opponent's player fouling out | No | Launch |
| Live Calls | Answers the same live yes/no prompt as the opponent, written from the game as it happens (see Live Calls) | Yes, 2 points to whoever is right when the other is wrong | Phase 1 (optional) |
| Clutch play | Once per duel, doubles one player's fourth quarter output | Yes | Phase 3 |
| Moment cards | Gets an auto-made shareable card when a player hits a milestone, such as 30 points or a double-double | No | Phase 3 |
| Spectator room | Friends watch a duel, cheer, and pick a winner | No | Phase 4 |
| Next-event picks | Predicts the next scoring play in a short window | Yes, small | Phase 4 |

Actions that move the score should open only in dead-ball windows or between periods. Feed delay differs across TV, streams, and the data source, so a live tap can reward whoever has the fastest stream. Moment cards use original art only.

## Ranked mode (Phase 2)

Ranked adds a global ladder for nights when no friend is around, with Elo matchmaking and one fixed rule set. Everyone plays the same NBA slate, so one worldwide queue works: the draft runs on a 45 second clock and the result comes from the stats.

- Fixed rules: Classic scoring and the Double Pick Coin. No custom modes. Calls (Phase 3) and Live Calls stay friend-duel options until fairness data is in.
- Ranked opens on slates of 3 or more games, so the pool is deep enough for drafting to be a skill. Friend duels stay open on any slate.
- An account and a verified phone number are required to queue.

**Rating.** New players start at 1000. Ratings update when a duel resolves, which can be after midnight Eastern for late games.

```latex
E_A = \frac{1}{1 + 10^{(R_B - R_A)/400}}

R_A' = R_A + K \, (S_A - E_A)
```

S is 1 for a win, 0.5 for a draw, and 0 for a loss. K is 40 for a player's first 20 ranked duels, 24 up to duel 100, and 16 after that. If the seat 2 win rate drifts outside 48 to 52 percent, add a fixed seat offset to the expected score.

**Matchmaking in waves.** Every 60 seconds, the queue is sorted by rating and paired from the top. Unmatched players widen their window by 100 points each wave, up to 400. After 3 waves, offer an unranked practice duel against a bot. Waves give better pairs than first-come matching while the player base is small.

| Tier | Rating |
| --- | --- |
| Rookie | Under 900 |
| Role Player | 900 to 1099 |
| Starter | 1100 to 1299 |
| All-Star | 1300 to 1499 |
| MVP | 1500 and up |
| Hall of Fame | Top 100 worldwide |

**Seasons.** About 8 weeks each. At the start of a season, ratings move halfway back to 1000. Rewards are cosmetic only.

**Anti-abuse**

- Rating changes halve after 3 ranked duels against the same opponent in a week
- One account per verified phone number
- Repeat abandoned drafts suspend ranked queueing for 24 hours
- Leaderboards: global, Canada, and friends

## Data and technical

One server-side service fetches all NBA data with nba\_api, and phones never call NBA.com directly. The library is an unofficial, open source client for NBA.com that covers official stats and live data such as the scoreboard ([nba\_api on GitHub](https://github.com/swar/nba_api)). Its latest listed release is v1.11.4 from February 20, 2026.

1. **Schedule sync.** Each morning in Eastern time, pull the day's slate and rosters.
2. **Live poller.** During games, poll the live scoreboard, box score, and play-by-play endpoints on a fixed interval, tuned once real rate limits are known.
3. **Store.** Write raw payloads and normalized stat lines to a cache and a database.
4. **Scoring engine.** Recompute every duel's Duel Score from the stored box scores. It is deterministic, so a disputed result can be replayed.
5. **Delivery.** Push score changes to phones over a live connection, and send notifications for lead changes and results.

The engine stores play-by-play from launch, because Live Calls resolve from it. Clutch play reuses it later.

**Risks with nba\_api**

- **No promises.** The README says NBA.com gives no notice of new, changed, or removed endpoints, so an endpoint can break on a game night. The v1.11.4 release notes show it happening: [PlayByPlayV2 and ScoreboardV2 were deprecated](https://github.com/swar/nba_api/releases) because NBA.com returns empty data for them. Plan for alerts and a fallback.
- **Terms of use.** The MIT license covers the library code, and NBA.com's [Terms of Use](https://www.nba.com/termsofuse) cover its platforms. Get a licensing opinion before launch, and price a licensed data feed as the fallback.
- **Hosting.** The library calls NBA.com directly, so test early whether requests from your cloud host are throttled or blocked.
- **Delay.** Treat live data as delayed against the TV broadcast, and use dead-ball windows for anything that moves the score.
- **Inactive status.** Confirm a source for injury and inactive status before tip-off, since it drives the free re-pick rule.

## Scope, metrics, and open questions

The MVP is friend duels plus the optional Live Calls mode, and ranked follows in Phase 2, because ranked queues need many players online at once and friend invites are how that base gets built.

1. **MVP: friend duels.** Challenge link, live draft with Double Pick, Classic scoring, live scores, win probability bar, chirps, result card, and head-to-head record, plus the optional Live Calls mode. Gate: accept rate, draft completion, and Live Calls answer rate hit target.
2. **Ranked.** Elo, wave matchmaking, tiers, seasons, and leaderboards. Gate: median queue time under 90 seconds on a 3-game slate.
3. **Calls and engagement.** Calls and Combos, Clutch play, and moment cards. Gate: Calls appear in at least 30 percent of duels.
4. **Later.** Spectator rooms, next-event picks, category rounds, and other leagues.

| Metric | Proposed target | What it tells you |
| --- | --- | --- |
| Challenge accept rate | 50% or more | Whether invite links convert |
| Draft completion | 90% or more | Whether a 3 minute draft works |
| Duels per active user per game night | 1.5 or more | Whether it is a nightly habit |
| Seat 2 win rate | 48 to 52 percent | Whether the Coin is balanced |
| Live Calls opt-in rate | 30% of duels or more | Whether the mode appeals |
| Live Calls answer rate | 85% of prompts answered by both players | Whether prompt timing works |
| Live Calls Yes rate | 45 to 55 percent per prompt type | Whether lines are set fairly |
| Median ranked queue time | Under 90 seconds | Whether ranked has enough players |

Targets are starting guesses to tune after the first playtests.

**Product risks**

- **No games, no duels.** The NBA has off days and an offseason. Plan an off-night surface (recaps, rankings) and other leagues.
- **Star-heavy drafts.** Points + rebounds + assists favors high-usage stars, so first picks can look obvious. Test category rounds and the Coin as fixes.
- **Gambling perception.** Calls resemble prop bets. Keep the wording, keep money out, and complete the legal review.

**Open questions**

- [x] Does an unused Coin expire, or convert into something small? - it expires
- [x] Should a duel allow async drafting when the opponent is offline? - no
- [x] Should ranked stay limited to slates of 3 or more games? - sure
- [ ] Which source gives injury and inactive status before tip-off? - TBD
- [x] What are the minimum age and account rules at launch? - all ages
- [x] Should launch be timed to opening night of the 2026-27 season? yes

* [x] What happens to a duel if a drafted player's game is postponed? - game is off

- [x] Should Live Calls assign opposite sides automatically (one takes Yes, the other No) instead of letting each duelist answer freely? - each duelist answers freely
- [x] How far does the live play-by-play feed trail the broadcast, and does it flag who is on the court? - doesn't matter rn
