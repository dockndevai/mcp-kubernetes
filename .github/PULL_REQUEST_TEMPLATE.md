## What does this PR do?

<!-- A short description of the change. -->

## Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] New/changed tools declare the correct `capability` (and `destructive: true` if they can lose data)
- [ ] Safe-by-default preserved: no tool is registered above its capability, and destructive operations stay behind their opt-in flag
- [ ] README / `.env.example` updated if tools or environment variables changed
