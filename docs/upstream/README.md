# Upstream issue drafts

Drafts of reports to downstream projects, for gaps Rosettalog observed on real engines. The
maintainer files them; once filed, add the issue URL here and to the gap's row in
[../rules-support-matrix.md](../rules-support-matrix.md#known-downstream-gaps-observed).

| Gap | Project | Existing reports (searched 2026-09-24) | Draft | Filed as |
|---|---|---|---|---|
| G1 | SigmaHQ/pySigma-backend-elasticsearch | ES\|QL: [#107](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/107) (open). Lucene/keyword: [#21](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/21), [#178](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/178) (both closed) | [g1-case-insensitivity.md](g1-case-insensitivity.md): a comment on #107 plus a new Lucene issue | – |
| G2 | SigmaHQ/pySigma-backend-elasticsearch | none found (searched: anchor, anchored, rlike, regex, regexp syntax, beginning of line, whole string). [#177](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/177) is a different regex bug | [g2-regex-anchors.md](g2-regex-anchors.md): new issue | – |
| G3 (Splunk) | SigmaHQ/pySigma-backend-splunk | none found (searched: correlation, bin, sliding, window, timespan, streamstats, temporal) | [g3-splunk-fixed-window.md](g3-splunk-fixed-window.md): new issue (warn/document, as agreed for ES\|QL in #182) | – |
| G3 (ES\|QL) | SigmaHQ/pySigma-backend-elasticsearch | [#182](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/182) (closed; tolerated by the Sigma spec, "should" warn, documentation issue) | no | – |
| G4 | SigmaHQ/pySigma-backend-elasticsearch | [#218](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/218), fixed by PR [#219](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/pull/219) (merged 2026-09-19, after 2.1.1: EQL no longer offers value_count) | no | – |
| G5 + G6 | SigmaHQ/pySigma-backend-elasticsearch | none found (searched: temporal_ordered, temporal ordered, sample, maxspan, with runs, EQL sequence, EQL temporal) | [g5-g6-eql-temporal.md](g5-g6-eql-temporal.md): one new issue | – |
| G7 | SigmaHQ/pySigma-backend-elasticsearch | related: #103 (open; mentioned in a comment), #109 (ES\|QL, closed) | [g7-eql-numeric-colon.md](g7-eql-numeric-colon.md): new issue | – |
| XQL (no pySigma 1.x backend) | 7RedViolin/pySigma-backend-cortexxdr | [#20](https://github.com/7RedViolin/pySigma-backend-cortexxdr/issues/20) (open): pySigma 1.x incompatibility | no | – |
| G8 | SigmaHQ/pySigma-backend-elasticsearch | none found (searched: regex~, EQL regex, regex case, insensitive regex) | [g8-eql-regex-case.md](g8-eql-regex-case.md): new issue; EQL whole-value matching added to the G2 draft | – |
