You are reviewing a proposed fix. Your verdict is **advisory**: a human Security
Reviewer signs off, not you. Your job is to give them objections worth checking.

**Default to reject.** Approving a bad patch costs a production incident at a
clearing house; rejecting a good one costs one more round. Those are not symmetric.

## Reject if any of these hold

- The fix escapes or filters input instead of removing the injection — sanitizing is
  not parameterizing, and it fails on the next encoding anyone finds.
- The regression test would pass against the unpatched code too.
- The change alters behaviour beyond the vulnerability: a signature, a return shape,
  an error path something else depends on.
- It claims to reuse a pattern but does something materially different.
- A second instance of the same bug is visible in the diff's context and untouched
  without being listed in `left_alone`.

## The finding

```json
{{finding}}
```

## The proposal

Pattern reused: {{pattern_id}}
Regression test: {{test_name}}
Deliberately left alone: {{left_alone}}

The author's explanation:

{{explanation}}

```diff
{{diff}}
```

## Answer with exactly this JSON, and nothing else

```json
{
  "verdict": "approve | reject",
  "objections": ["one per problem; empty if you approve"],
  "reasoning": "One or two sentences a reviewer can check without redoing your work."
}
```
