// SPDX-License-Identifier: GPL-2.0-only
/// Use bitmap_empty rather than bitmap_weight() == 0 etc
///
// Confidence: High
// Copyright: (C) 2022 Yury Norov
// URL: http://coccinelle.lip6.fr/
// Comments:
// Options: --no-includes --include-headers

virtual org
virtual report
virtual context
virtual patch

@rfull depends on !patch@
position p;
expression E1, E2;
binary operator cmp = {==, !=, <};
@@

 bitmap_weight(E1,E2) cmp@p E2

@script:python depends on report@
p << rfull.p;
@@

coccilib.report.print_report(p[0], "ERROR: use bitmap_full()")

@script:python depends on org@
p << rfull.p;
@@

@rempty1 depends on !patch@
position p;
statement S;
@@

 if (bitmap_weight@p(...)) S

@script:python depends on report@
p << rempty1.p;
@@

for p0 in p:
        coccilib.report.print_report(p0, "ERROR: use !bitmap_empty()")

@script:python depends on org@
p << rempty1.p;
@@

@rempty depends on !patch@
position p;
@@

	bitmap_weight@p(...) == 0

@script:python depends on report@
p << rempty.p;
@@

for p0 in p:
        coccilib.report.print_report(p0, "ERROR: use bitmap_empty()")

@script:python depends on org@
p << rempty.p;
@@

@not_rempty depends on !patch@
position p;
@@

 bitmap_weight(...) @p> 0

@script:python depends on report@
p << not_rempty.p;
@@

for p0 in p:
        coccilib.report.print_report(p0, "ERROR: use \"!bitmap_empty()\"")

@script:python depends on org@
p << not_rempty.p;
@@


@rcmp depends on !patch@
expression exp;
binary operator cmp = {>, <, >=, <=, ==, !=};
position p;
@@

 bitmap_weight(...) cmp@p exp

@script:python depends on report@
p << rcmp.p;
@@

for p0 in p:
        coccilib.report.print_report(p0,
		"WARNING: use bitmap_weight_{gt,lt,ge,le,eq} as appropriate")

@script:python depends on org@
p << rcmp.p;
@@
