// SPDX-License-Identifier: GPL-2.0-only
/// Use cpumask_empty rather than cpumask_weight() == 0 etc
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

@rempty1 depends on !patch@
position p;
statement S;
@@

if (cpumask_weight@p(...)) S

@script:python depends on report@
p << rempty1.p;
@@

for p0 in p:
        coccilib.report.print_report(p0, "ERROR: use !cpumask_empty()")

@script:python depends on org@
p << rempty1.p;
@@

@rcmp depends on !patch@
expression exp;
binary operator cmp = {>, <, >=, <=, ==, !=};
position p;
@@

 cpumask_weight(...) cmp@p exp

@script:python depends on report@
p << rcmp.p;
@@

for p0 in p:
        coccilib.report.print_report(p0,
		"ERROR: use cpumask_weight_{empty,full,gt,lt,ge,le,eq} as appropriate")

@script:python depends on org@
p << rcmp.p;
@@
