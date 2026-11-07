# Rules for every agent working in this repo

- Author and committer of every commit: `Naresh R <72620370+Naresh23032003@users.noreply.github.com>`. No `Co-authored-by` or tool trailers.
- Conventional Commits (`feat(scope): …`, `fix: …`, `test: …`, `docs: …`, `chore: …`). One task, one branch (`<type>/<issue>-<slug>`), one small PR.
- The issue is the spec. Do exactly its scope; list anything else as follow-ups in the PR.
- TypeScript strict. Write or update tests with every change. Run `npm ci`, `npm run lint`, `npm test` and the Docker build before opening the PR, and paste the results in the PR body.
- Security first: no secrets in code, logs or fixtures; read config from the environment or `gateway.toml`; never use `child_process` or `eval`; escape everything rendered to HTML.
- No new dependency without a one-line reason in the PR.
- PR body: what changed and why, how it was tested (commands and results), risks and follow-ups, `Closes #<issue>`.
