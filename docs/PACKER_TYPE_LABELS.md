# Empirical Packer Type Labels

Runtime-packer complexity on the **Ugarte Type I–VI** scale (*SoK: Deep Packer Inspection*, IEEE S&P 2015) via the certified QEMU-TCG write→execute oracle. Per Ugarte Sec V-C a Type is the **highest complexity observed** across runs (no-observation runs abstain). **TYPE_0** = transformation without runtime unpacking (PE-header/EP mutators). Remaining conditions carry the pipeline's own verdict (no unpacking observed / no execution / trace loss) — the SoK excludes non-unpacking samples, so these are a valid empirical outcome, not a labeling failure.

**102 conditions** · 92 typed · 10 pipeline-unresolved. 2026-07-24.

## Type distribution
| Type | Count |
|------|------:|
| TYPE_0 | 1 |
| TYPE_I | 69 |
| TYPE_II | 5 |
| TYPE_III | 5 |
| TYPE_IV | 7 |
| TYPE_V-F | 1 |
| TYPE_VI-F | 4 |
| unresolved | 10 |

## Typed packers (92)

| Packer family | Version | Test case | Type | Rule |
|---|---|---|---|---|
| astral_pe | 1.6.0.0 | ASTRAL_001_DEFAULT_MUTATION | **TYPE_0** | mutator |
| acprotect_std_Standard__installer | ? | . | **TYPE_I** | exact |
| beroexepacker | 1.00.2017.01.27 | BEP_001_DEFAULT | **TYPE_I** | exact |
| eronona | 1.0 | ERONONA_001_DEFAULT | **TYPE_I** | exact |
| fsg | 1.3 | FSG_V13_001_DEFAULT | **TYPE_I** | max-obs |
| hackupx | 1.00 | HACKUPX_001_MUTATE | **TYPE_I** | exact |
| mew | 1.1_SE | . | **TYPE_I** | exact |
| npack | 1.1.300.2006 | . | **TYPE_I** | exact |
| packman | 1.0 | . | **TYPE_I** | exact |
| pe_diminisher | 0.1 | . | **TYPE_I** | exact |
| pepacker | 1.0 | PEPACKER_001_DEFAULT | **TYPE_I** | exact |
| rlpack | 1.21_Basic | . | **TYPE_I** | exact |
| upx | 0.60 | UPX_V060_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.61 | UPX_V061_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.62 | UPX_V062_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.70 | UPX_V070_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.71 | UPX_V071_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.72 | UPX_V072_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.762b | UPX_V762BETA_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.763b | UPX_V763BETA_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.80 | UPX_V080_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.81 | UPX_V081_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.82 | UPX_V082_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.83 | UPX_V083_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.84 | UPX_V084_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.896b | UPX_V896BETA_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.90 | UPX_V090_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.92 | UPX_V092_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.93 | UPX_V093_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.94 | UPX_V094_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.99 | UPX_V099_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.991 | UPX_V0991_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.992 | UPX_V0992_001_DEFAULT | **TYPE_I** | exact |
| upx | 0.993 | UPX_V0993_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.00 | UPX_V100_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.01 | UPX_V101_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.02 | UPX_V102_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.03 | UPX_V103_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.04 | UPX_V104_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.05 | UPX_V105_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.06 | UPX_V106_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.07 | UPX_V107_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.08 | UPX_V108_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.20 | UPX_V120_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.21 | UPX_V121_001_DEFAULT | **TYPE_I** | exact |
| upx | 1.22 | UPX_V122_001_DEFAULT | **TYPE_I** | exact |
| upx | 3.95 | UPX_V395_001_DEFAULT | **TYPE_I** | exact |
| upx | 3.96 | UPX_V396_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.0.0 | UPX_V400_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.0.1 | UPX_V401_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.0.2 | UPX_V402_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.1.0 | UPX_V410_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.2.0 | UPX_V420_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.2.1 | UPX_V421_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.2.2 | UPX_V422_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.2.3 | UPX_V423_001_DEFAULT | **TYPE_I** | exact |
| upx | 4.2.4 | UPX_V424_001_DEFAULT | **TYPE_I** | exact |
| upx | 5.0.0 | UPX_V500_001_DEFAULT | **TYPE_I** | exact |
| upx | 5.0.1 | UPX_V501_001_DEFAULT | **TYPE_I** | exact |
| upx | 5.0.2 | UPX_V502_001_DEFAULT | **TYPE_I** | exact |
| upx | 5.1.0 | UPX_001_DEFAULT | **TYPE_I** | exact |
| upx | 5.1.1 | UPX_V511_001_DEFAULT | **TYPE_I** | exact |
| upx_scrambler | 3.0.4 | . | **TYPE_I** | exact |
| upx_scrambler | 306_unknown | . | **TYPE_I** | exact |
| upx_scrambler_rc103_unknown | ? | . | **TYPE_I** | exact |
| upx_scrambler_rc105_unknown | ? | . | **TYPE_I** | exact |
| upx_scrambler_rc1_RC1 | ? | . | **TYPE_I** | exact |
| upx_scrambler_rc1b10_RC1b10 | ? | . | **TYPE_I** | exact |
| xcomp | 0.97 | XCOMP_001_DEFAULT | **TYPE_I** | exact |
| yoda_protector | 1.0 | . | **TYPE_I** | exact |
| kkrunchy | 0.23_alpha | KKRUNCHY_001_DEFAULT | **TYPE_II** | exact |
| mpress | 1.27 | MPRESS_V127_001_DEFAULT | **TYPE_II** | exact |
| mpress | 2.19 | MPRESS_001_DEFAULT | **TYPE_II** | exact |
| yoda_crypter | 1.2 | . | **TYPE_II** | exact |
| yoda_crypter | 1.3 | . | **TYPE_II** | max-obs |
| jdpack | 1.00 | . | **TYPE_III** | exact |
| petite | 2.2 | PETITE_V22_001_DEFAULT | **TYPE_III** | exact |
| petite | 2.3 | PETITE_V23_001_DEFAULT | **TYPE_III** | exact |
| petite | 2.4 | PETITE_001_DEFAULT | **TYPE_III** | exact |
| shrinker | 3.4_Demo | . | **TYPE_III** | exact |
| alienyze_protector | 1.4 | . | **TYPE_IV** | max-obs |
| amber | 2.0 | AMBER_V2_002_REFLECTIVE | **TYPE_IV** | max-obs |
| enigma_protector | 7.80_build_20250205 | ENIGMA_001_DEFAULT | **TYPE_IV** | max-obs |
| exe32pack | 1.42 | EXE32PACK_001_DEFAULT | **TYPE_IV** | exact |
| nspack | 3.7 | . | **TYPE_IV** | exact |
| upack | 0.399__Brute | UPACK_001_DEFAULT | **TYPE_IV** | exact |
| yoda_protector | 1.02 | . | **TYPE_IV** | exact |
| winupack | 0.39 | . | **TYPE_V-F** | max-obs |
| asm_guard | 2.9.4 | . | **TYPE_VI-F** | max-obs |
| molebox | 4.6000 | MOLEBOX_001_DEFAULT | **TYPE_VI-F** | max-obs |
| pelock | 2.40 | . | **TYPE_VI-F** | exact |
| zprotect | 1.4.2.0 | . | **TYPE_VI-F** | max-obs |

## Pipeline-unresolved (10)

Empirical pipeline verdict; W→X oracle observed no unpacking (see manifest `needs_pipeline`; obsidium pending SHA-gate re-sample for pass-through).

| Packer family | Version | Pipeline verdict |
|---|---|---|
| simpledpack | 0.5.3 | `no_execution` |
| themida | 3.2.4.34 | `no_runs` |
| armadillo | 252b2 | `no_unpacking_observed` |
| kkrunchy | 0.23_alpha_2 | `no_unpacking_observed` |
| obsidium | 1.5.2.11 | `no_unpacking_observed` |
| pezor | 3.3.0 | `no_unpacking_observed` |
| telock | 0.98 | `no_unpacking_observed` |
| yoda_protector | 1.01.2 | `no_unpacking_observed` |
| yoda_protector | 1.03.3 | `no_unpacking_observed` |
| yoda_protector | 1.03.2 | `trace_loss` |
