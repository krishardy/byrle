# Contributing

byrle is licensed under Apache-2.0: see [LICENSE](LICENSE). A contribution is accepted
under the same licence.

## Sign-off

Every commit carries a sign-off, a line certifying the Developer's Certificate of Origin
below:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it from `user.name` and `user.email`. The name is your real name, not
a pseudonym. A pull request with a commit that is not signed off fails CI's `signed-off`
job, `make commit-fixup CHECKS=sign-off`, until it is: `git commit --amend -s` for the last
commit, or `git rebase --signoff origin/main` for a branch. The sign-off must carry the commit
author's email.

No contributor licence agreement is asked for.

## Signatures

Every commit is signed, with a GPG, SSH or S/MIME key registered on your GitHub account
(Settings, "SSH and GPG keys"), and the commit's email is one of that account's. A pull
request with a commit GitHub does not show as "Verified" fails CI's `signatures` job,
`make pr-signatures PR=<number>`. `git commit -S` signs one commit. `git config
commit.gpgsign true` signs each. `make commit-fixup CHECKS=signature FIX=1` signs the
commits on a branch that are not pushed.

## Developer's Certificate of Origin

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Before a pull request

`make lint`, `make test` and `make coverage` pass. `make coverage` runs on a pinned
nightly toolchain, which `make dev-setup` installs; see
[coverage-counts-library-code-only](docs/engineering_decisions/0077-coverage-counts-library-code-only.md).
CLAUDE.md lists the project's standards, including 100% unit test coverage of the library
and documentation of each engineering decision in `docs/engineering_decisions/`.

A report of a security vulnerability goes through [SECURITY.md](SECURITY.md), not an issue
or pull request.
