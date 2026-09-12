# Merge golden files

One policy per `.yaml`, and the merge of it per `.merged`. The test in
`src/policy/merge.rs` renders every ecosystem in each file and compares.

They exist because the merge's output is a judgement, not a value: "this override
loosened the policy above it" is the thing an operator acts on, and a change to it should
show up as a diff in review rather than as a test that still passes. Assertions cover the
cases one at a time; these cover what the whole report looks like.

Every file is merged against **2026-09-12**, fixed so an acknowledgment's expiry does not
depend on when the suite runs.

## Refreshing them

`WAHAROA_BLESS=1 cargo test --lib merge` rewrites every `.merged` from the current code.
Read the diff before committing it: the point of the file is that a change to the report
has to be looked at, and blessing without reading throws that away.

## Adding one

Write the `.yaml`, bless, read what came out. A case is worth adding when it is a shape
the merge decides differently, not when it is another example of one already here.
