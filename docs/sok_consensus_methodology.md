# SoK consensus methodology: does exact-trace consensus over-reject?

Claims document for the labeling decision on packers that fail the 6/6 exact-trace
consensus gate (amber, enigma, zprotect, yoda_crypter). Every claim is numbered and
cited. Quotes marked **[PDF]** were extracted verbatim from the local copy of the paper
(`docs/SoK_ Deep Packer Inspection_ A Longitudinal Study of the Complexity of Run-Time
Packers - ugarte2014.pdf`) via `pdftotext`; ligatures (fi/fl) restored where the
extractor dropped them. Claims that could not be verified against a primary source are
marked **UNVERIFIED**. The recommendation in Section 4 is opinion and is separated from
the cited claims.

**Primary source (S1):** Xabier Ugarte-Pedrero, Davide Balzarotti, Igor Santos, Pablo
G. Bringas. "SoK: Deep Packer Inspection: A Longitudinal Study of the Complexity of
Run-Time Packers." IEEE Symposium on Security and Privacy (S&P), 2015, pp. 659–673.
IEEE Xplore document 7163053. (DOI is 10.1109/SP.2015.46 per common citation practice
— digit-level DOI **UNVERIFIED**; the Xplore document number and page range are
verified via IEEE Xplore / dblp.)

---

## Q1 — How does the SoK actually assign a Type?

**C1. The taxonomy is assigned per execution trace by structural features, defined in
Section II ("Packer Complexity Types", Figure 1, p. 661–662).** [PDF]

> "The features we presented so far can be used to precisely characterize the behavior
> of a packer. In this section, we present a simplified hierarchy to combine all of
> them together in a single, more concise classification. Figure 1 shows our taxonomy,
> containing six types of packers with an increasing level of complexity."

Each Type is defined by *positively observed* structural evidence: Type I "a single
unpacking routine is executed before transferring the control to the unpacked
program"; Type II "multiple unpacking layers, each one executed sequentially"; Type
III adds "loops"; Type IV has packer code "interleaved with the execution of the
original program"; Types V/VI are frame-wise revelation of the original code. (S1,
Sec. II.)

**C2. The concrete decision procedure (Section III, "Separating Type-III from
Type-IV" / "Separating Type-IV from Type-V and Type-VI", p. 665–666) walks a single
instruction trace and, on ambiguity, defaults to the LOWER type.** [PDF]

> "Starting from the end of the instruction trace, we move backward and consider the
> transitions between the original code and the packer code. If we only find a
> transition from the unpacking routine to the original code (i.e., tail transition),
> then the packer is considered cyclic (Type-III), otherwise it is interleaved
> (Type-IV or higher). The only uncertain case happens when all the code is flagged as
> belonging to the packer. ... In this case, it is not possible to distinguish if the
> packer and application code are interleaved or not. Therefore, for the lack of
> evidence, we assume that the packer belongs to Type-III."

The classifier is evidence-monotone by construction: positive evidence promotes a
sample to a higher type; missing evidence demotes it. (S1, Sec. III.)

**C3. The evaluation runs each sample ONCE. There is no repetition and therefore no
cross-run reconciliation rule anywhere in the paper.** [PDF] (S1, Sec. V-A, "Analysis
Infrastructure", p. 667):

> "We analyzed every sample in our framework using 20 virtual machines configured with
> two CPUs and 4 GB of RAM each. The analysis of the samples was automated and each
> sample was run until one of the following condition was satisfied: • All the
> processes under analysis terminated their execution. • An exception was produced and
> not recovered within two minutes. ... • The monitored processes were idle for more
> than two consecutive minutes. • A maximum time-out of 30 minutes was reached."

Negative search result (verifiable by grepping the extracted text): the strings
"repeat", "repetition", "re-run", "multiple runs", "non-determinism"/"nondeterminism"
do not occur in the paper. The paper never requires — or even discusses — agreement
across repeated executions of the same sample.

**C4. Where the paper DOES aggregate multiple observations of "the same packer" (across
versions/configurations), it reports the MAXIMUM observed complexity, not a consensus.**
[PDF] (S1, Sec. V-C, "Packers Distribution", p. 668, describing Table II):

> "Table II shows the distribution of the most common packers over the years according
> to Sigbuster ... The table also presents the highest complexity observed among the
> different packer versions tested during the experiments."

This is the only aggregation-across-observations rule stated in the paper, and it is
"highest complexity observed."

---

## Q2 — Is the scale monotone in "unpacking observed"? Is no-observation evidence of simplicity?

**C5. In the paper's own evaluation, a run in which no unpacking is observed is
EXCLUDED from typing — it is not assigned Type I or any type.** [PDF] (S1, Sec. V-D,
"Analysis of Custom Packers", p. 668):

> "To study the complexity and the characteristics of these packers we run our
> analysis tool on 7,729 malware binaries ... Despite all having a section with
> entropy higher than 7, only 6,088 samples presented an unpacking behavior during our
> analysis. Table I shows the packer complexity classes in both datasets ..."

Arithmetic check on Table I [PDF]: the custom-packer column (443 + 752 + 3993 + 843 +
46 + 11) sums to exactly 6,088 — i.e., the type distribution is computed only over
the samples where unpacking WAS observed. The 1,641 no-unpacking runs receive no type.
The paper treats "no unpacking observed" as absence of evidence, not as evidence of a
Type-0/Type-I packer.

**C6. The paper explicitly acknowledges that its observation can be defeated
(evasion) and that its type-separating heuristic has unmeasured accuracy — i.e., its
labels are best-effort observations, not ground truth.** [PDF] (S1, Sec. VI,
Discussion, p. 670–671):

> "The presented framework was developed over a whole-emulation solution: TEMU. While
> it is true that some malware samples may implement specific anti-QEMU techniques,
> other approaches such as debugging or binary instrumentation are also susceptible of
> being detected ..."

> "... the distinction between Type-III and Type-IV, and between Type-IV and
> Type-V/Type-VI require to locate the memory regions where the original code resides.
> In order to confront this problem we designed a heuristic and manually verified its
> effectiveness in a number of real examples. Unfortunately, due to the lack of
> labeled datasets, and therefore of a ground truth, it is not possible to measure the
> accuracy of this heuristic beyond the manual analysis already conducted."

**C7. Correction to an internal premise: the paper does NOT acknowledge a
"mapped-section blindness."** On the contrary, it claims to handle mapping/un-mapping
[PDF] (S1, Sec. III-A/B, p. 663): "Our framework is able to track many different
techniques ... including remote memory writes, shared memory sections, disk I/O, and
memory-mapped files. It also monitors memory un-mapping and memory deallocation
events." If our tracer has a mapped-section blind spot, that limitation is OURS, not
one the paper admits; it still functions as a false-negative mechanism on our side,
but it should not be cited to the paper.

**C8. Monotonicity conclusion (inference from C1–C6, labeled as such).** Within the
paper's model, layers and frames are created only by positively observed
write-then-execute events; the classifier promotes types only on positive evidence
and demotes on missing evidence (C2), non-observing runs are dropped rather than
labeled simple (C5), and cross-observation aggregation takes the maximum (C4).
Under-observation (evasion, truncation, tracer blind spots) removes evidence and can
only lower the assigned type; there is no mechanism in the model by which
under-observation raises it. Therefore, in the paper's framework, an observed Type is
a LOWER BOUND on the packer's complexity, and "no unpacking observed" is a failed
measurement, not a datapoint for simplicity. This exact statement does not appear
verbatim in the paper (the paper never discusses cross-run reconciliation because it
runs once — C3); it is the direct consequence of C2+C4+C5. Status: supported
inference, not a quotation.

---

## Q3 — Is our 6/6 exact-consensus gate stricter than the paper or the field?

**C9. Strictly stricter than the SoK itself.** The SoK assigns a type from ONE run per
sample with no repetition requirement (C3), and when it has multiple observations per
packer family it reports the maximum (C4). Our gate (identical Type across 6
repetitions of ≥2 payloads = 12+ agreeing traces) demands strictly more agreement than
the paper that defines the scale demanded of itself. [Derived from C3, C4.]

**C10. Ugarte-Pedrero et al.'s own follow-up treats a single execution as an
under-approximation of unpacking behavior and adds exploration to observe MORE.**
Source (S2): Xabier Ugarte-Pedrero, Davide Balzarotti, Igor Santos, Pablo G. Bringas.
"RAMBO: Run-Time Packer Analysis with Multiple Branch Observation." DIMVA 2016, pp.
186–206 (venue/authors/pages verified via dblp/ResearchGate/EURECOM). The paper's
premise is that some packers "only decrypt individual regions of code on demand,
re-encrypting them again when they are not running," so a single concrete path reveals
only part of the unpacked code, motivating multiple-branch observation to increase
coverage — i.e., more observation reveals more complexity, never less. Exact internal
quotes: **UNVERIFIED** (no local PDF); title, venue, and abstract-level premise
verified.

**C11. Mantovani et al. (co-authored by Ugarte-Pedrero) determine "packed" from
positive dynamic evidence of written-then-executed memory; absence of such evidence in
a run is not treated as proof of non-packing (their headline result is that packing is
systematically under-detected by static proxies).** Source (S3): Alessandro Mantovani,
Simone Aonzo, Xabier Ugarte-Pedrero, Alessio Merlo, Davide Balzarotti. "Prevalence
and Impact of Low-Entropy Packing Schemes in the Malware Ecosystem." NDSS 2020
(venue/authors verified via NDSS symposium site and dblp; paper PDF at
ndss-symposium.org). Their specific per-sample run-count and any cross-run rule:
**UNVERIFIED** (not checked against the PDF text).

**C12. The wave/layer lineage models complexity per concrete execution trace — a
per-trace lower bound — with no consensus-across-runs requirement.** Source (S4):
Guillaume Bonfante, José Fernandez, Jean-Yves Marion, Benjamin Rouxel, Fabrice
Sabatier, Aurélien Thierry. "CoDisasm: Medium Scale Concatic Disassembly of
Self-Modifying Binaries with Overlapping Instructions." ACM CCS 2015 (venue/authors
verified via ACM CCS 2015 program and HAL). CoDisasm recovers "waves" (their
layer-analogue) from a concrete execution of the sample combined with static
disassembly; waves are whatever that execution exhibited. Exact internal quotes:
**UNVERIFIED** (no local PDF).

**C13. Negative claim: I found no top-tier dynamic-packer-analysis work that requires
identical complexity labels across repeated executions before assigning a label.**
Status: **UNVERIFIED as a universal negative** (absence of evidence across the sources
examined: S1 read in full via text extraction; S2–S4 checked at metadata/abstract
level). It is offered as "no precedent found," not "no precedent exists."

---

## Q4 — RECOMMENDATION (opinion; not a cited claim)

**Assign the majority type via a "maximum observed complexity" rule; exact 6/6
consensus is not required by the SoK and is stricter than its own methodology.**

Defensible rule, faithful to S1:

1. Treat `UNRESOLVED_NO_UNPACKING_OBSERVED` reps as failed measurements, not as
   competing labels (C5). They abstain; they do not vote.
2. Among reps that DID observe unpacking, assign the **maximum** Type observed,
   because an observed Type is a lower bound on complexity (C8): under-observation
   (truncated run, evasion triggered, tracer blind spot such as our mapped-section gap
   — see C7) can only depress the observed Type, and the SoK classifier itself
   defaults downward on missing evidence (C2). A lower-Type minority rep (yoda_crypter's
   single TYPE_I among five TYPE_II; enigma's single TYPE_I among four TYPE_IV) is
   exactly the signature of under-observation, and cannot outvote positive structural
   evidence of the higher Type.
3. Keep the cross-payload half of our gate — require the maximum Type to be observed
   at least once in ≥2 distinct payloads. That preserves what our gate adds beyond
   the SoK (payload generalization) while dropping only the part with no basis in the
   paper (rep-level unanimity). Even so gated, we remain stricter than S1, which
   labeled from a single run (C3) and aggregated by maximum (C4).
4. Record the full per-rep vector (e.g., `amber: 4xTYPE_IV, 2xNO_OBS -> TYPE_IV`) as
   provenance so the consensus failure stays auditable.

Under this rule: amber → TYPE_IV, enigma → TYPE_IV, yoda_crypter → TYPE_II, and
zprotect analogously if its rep vector matches the same pattern (majority positive
Type + no-observation/lower-Type minority — its vector was not provided in this
analysis and must be checked before labeling).

One caution: rule 2's monotonicity argument is strongest when the minority is
no-observation or a lower type. If two DIFFERENT positive types ever split without an
under-observation explanation (e.g., 3xTYPE_III vs 3xTYPE_V), max-rule still applies
per C4/C8 but deserves a manual trace review before labeling, since the III/IV and
IV/V boundaries rest on the heuristic whose accuracy the paper itself declines to
quantify (C6).

---

## Tally

- Total numbered claims: 13 (C1–C13).
- Fully verified against primary text: C1–C7 (direct PDF quotes + arithmetic check).
- Supported inference/derivation, explicitly labeled: C8, C9.
- Metadata-verified, internal quotes UNVERIFIED: C10, C11, C12.
- UNVERIFIED as stated (universal negative): C13.
- One DOI digit-string flagged UNVERIFIED in S1's citation block.

---

## Verification (independent)

Adversarial re-verification performed 2026-07-24 by independently re-extracting the
local PDF with `pdftotext` (74,775 bytes of text) and locating every load-bearing
passage by grep, without relying on this document's quotes. Line numbers refer to the
fresh extraction; ligatures (fi/fl) are dropped by the extractor ("satised",
"agged", "les").

**V1. Single run, no repetition (C3) — CONFIRMED.** Found verbatim in Sec. V-A
"Analysis Infrastructure" (extraction lines 902–906): "The analysis of the samples
was automated and each sample was run until one of the following condition was
satised:" followed by the four termination bullets (all processes terminated;
unrecovered exception after two minutes; idle for two consecutive minutes; 30-minute
time-out). Adversarial counter-search: `repeat`, `re-run`, `rerun`, `multiple runs`,
`twice`, `two runs`, `several runs`, `re-execut`, `nondeterminis` — zero hits in the
entire text. Every occurrence of "majority" (7 hits) refers to within-trace code/frame
heuristics or dataset prevalence, never to voting across runs. No repetition or
cross-run reconciliation exists anywhere in the paper.

**V2. Maximum-observed aggregation (C4) — CONFIRMED.** Found in Sec. V-C "Packers
Distribution" (heading at line 936, passage at 972–975, page marker 668): "The table
also presents the highest complexity observed among the different packer versions
tested during the experiments." "Highest" is unambiguous — a maximum, not a majority
or mean — and this is the only cross-observation aggregation rule stated in the paper.
Nuance: it aggregates across packer *versions/configurations*, not across repeated
runs of one sample (the paper never repeats runs, per V1), so extending it to reps is
an inference, not a direct prescription.

**V3. No-unpacking runs excluded from typing (C5) — CONFIRMED.** Found in Sec. V-D
"Analysis of Custom Packers" (lines 992–994): "Despite all having a section with
entropy higher than 7, only 6,088 samples presented an unpacking behavior during our
analysis. Table I shows the packer complexity classes in both datasets". Independent
arithmetic on the extracted Table I custom column: 443 + 752 + 3993 + 843 + 46 + 11 =
6,088 exactly; the off-the-shelf column sums to 685, the full off-the-shelf dataset.
The 1,641 custom samples (7,729 − 6,088) with no observed unpacking receive no type
anywhere — they abstain rather than being labeled Type-I.

**V4. Downward default on missing evidence (C2) — CONFIRMED.** Found in the
"Separating Type-III from Type-IV" procedure (lines 685–697, Complexity Analysis
section, page marker 666): "In this case, it is not possible to distinguish if the
packer and application code are interleaved or not. Therefore, for the lack of
evidence, we assume that the packer belongs to Type-III." — the lower of the two
candidates. Also re-checked the Type-IV vs V/VI separation (lines 698–707): promotion
to V/VI requires positive evidence ("If the majority of the code ... contains multiple
frames"); no upward default exists anywhere in the classifier.

**V5. Mapped-section handling claimed by the paper (C7) — CONFIRMED.** Found in Sec.
III-A "Execution tracing" (lines 483–495): "Our framework is able to track many
different techniques that can be used by two processes to interact, including remote
memory writes, shared memory sections, disk I/O, and memory-mapped les. It also
monitors memory un-mapping and memory deallocation events" — and it treats page
un-mapping as re-packing. The paper claims coverage of mapped sections; any
mapped-section blindness is our tracer's limitation, correctly not cited to the paper.

**Tally: 5 CONFIRMED, 0 REFUTED, 0 UNVERIFIABLE.**

**Overall verdict: YES** — "assign the maximum observed Type across reps, with
no-observation reps abstaining and ≥2 distinct payloads required" is paper-faithful
(strictly stricter than the paper, which typed each sample from one run and aggregated
by maximum). Strongest supporting quote: "The table also presents the highest
complexity observed among the different packer versions tested during the
experiments." (Sec. V-C, p. 668). One honest caveat, already flagged in C8: the paper
never faced the repeated-runs question, so the max-across-reps rule is
consistent-by-extension with its methodology, not a rule it states.
