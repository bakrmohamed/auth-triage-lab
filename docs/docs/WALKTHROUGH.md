# Walkthrough and interview notes

## Explain the problem in 30 seconds

“An analyst needs more than a suspicious count. This tool takes normalized authentication events, groups them into short UTC windows and reports the exact rows behind three simple rules. It runs offline. The point is to explain a match and its limits, not automatically declare a compromise.”

Use that as a description of the project, not a claim about a production deployment or personal employment history.

## Follow one finding through the code

1. Run `python -m authtriage examples/auth-events.jsonl --format markdown`.
2. Open `examples/auth-events.jsonl`. Lines 3 to 7 are five failures for one source, user and service, over four minutes.
3. `read_events` keeps physical line numbers. `parse_event` rejects unsupported fields, validates the IP and normalizes offset-aware timestamps to UTC.
4. `analyze` sorts by event time. It maintains failure deques for each source/user/service and source/service group.
5. At each event it removes failures older than the inclusive window. The fifth failure crosses the threshold and creates a finding.
6. Line 8 is a success. The five failures still lie inside its window. The success finding includes all six evidence events. The pair's failure episode is then cleared.
7. Lines 9 to 13 are failures for five different users. They trigger the multi-user rule independently of the single-user rule.
8. Inspect the JSON. Evidence includes the physical line, normalized timestamp, source, user, service and outcome. Nothing depends on the machine's current time.

## Questions worth being ready for

**Why not count by minute?**

A fixed minute bucket can split a burst across its boundary. A sliding window evaluates the preceding interval at each event. It still misses slow behavior beyond that interval.

**Why sort first?**

A batch export may not be chronological. Sorting makes comparisons consistent. For exactly tied timestamps, the input order is used because the log provides no finer ordering. That is a documented limitation, not evidence of actual causal order.

**Why use a deque?**

Old failures leave from the front, and new failures enter at the back. Those operations are cheap. Sorting is `O(n log n)`, but the complete algorithm is not guaranteed linear afterward: recalculating distinct-user sets and copying alert evidence can dominate dense traffic. A counter per source is a useful future optimization.

**What happens after a burst triggers?**

It stays active until an event for that group finds fewer than the threshold failures in its window. This avoids one alert per failure. A successful login closes only its source/user/service episode.

**Is a success after five failures a compromise?**

No. It might be a user remembering their password. Review MFA, device details and session activity before making a conclusion. The “high” label means “review sooner,” not “confirmed malicious.”

**Can a password spray be missed?**

Yes. Distributed sources, fewer targeted users, slow attempts and split input files can evade this rule. The tool says “possible spray pattern,” not “detected password spraying with measured accuracy.”

**How do the tests help?**

They lock down boundaries and evidence, not just alert counts. There are CLI tests and a seeded randomized comparison against a simple reference implementation. Passing tests reduces regressions; it does not prove there are no defects.

**What would production require?**

A source-specific parser, durable state, deduplication, resource budgets, access controls, labeled evaluation data, operational monitoring and analyst feedback. This project deliberately does not claim those capabilities.

## شرح بالمصري

المشروع بياخد ملف لوجات دخول متحوّل لصيغة موحدة، ويطلع الحالات اللي محتاجة مراجعة ومعاها السطور اللي سببت التنبيه. مش بيتصل بأي جهاز، ومش بيجرّب باسوردات، ومش بيقفل حسابات.

- أول قاعدة: محاولات فاشلة كتير لنفس المستخدم، من نفس العنوان، على نفس الخدمة، في وقت قصير.
- تاني قاعدة: نفس المصدر بيحاول يدخل على مستخدمين مختلفين. ده نمط ممكن يشبه password spray، بس ممكن يكون وراه سبب عادي.
- تالت قاعدة: دخول ناجح بعد محاولات فاشلة كتير. لازم نراجع هل الدخول متوقع ولا لأ، مش نحكم إنه اختراق من العدد بس.

كل الأوقات بتتحول لـUTC، والملف بيترتب حسب الوقت. لو في سطر غلط بيتسجل رقمه وسبب رفضه من غير نسخ محتواه الغلط في رسالة الخطأ. مع `--strict` البرنامج بيطلع التقرير وبرضه يرجع كود خروج `2` عشان أي تشغيل آلي يعرف إن الداتا ناقصة.

في الإنترفيو افتح المثال وشغّله، وبعدها امشي على السطور والدليل. لو لسه مش فاهم جزء، راجعه وجرّب تغييره في نسخة محلية قبل ما تقول إنك فاهمه. متقولش إنه اتستخدم في شركة أو بيكشف كل الهجمات، لأن المشروع مش بيثبت ده.
