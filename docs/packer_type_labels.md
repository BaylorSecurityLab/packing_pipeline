# Empirical Packer Type Labels

Runtime-packer complexity labels on the **Ugarte et al. Type I–VI** scale (*SoK: Deep Packer Inspection*, IEEE S&P 2015), measured on the certified QEMU-TCG write→execute backend. Only **exact-trace consensus** (same Type across every repetition of ≥2 distinct payloads) yields a Type; genuine protectors whose unpacking the write→execute oracle cannot observe remain **UNRESOLVED**, annotated with the orthogonal `protection_class`.

**Final — complete run:** all 102 conditions labeled (82 typed, 20 unresolved). 2026-07-24.

## Type distribution
| Type | Count |
|------|------:|
| TYPE_I | 68 |
| TYPE_II | 4 |
| TYPE_III | 5 |
| TYPE_IV | 4 |
| TYPE_VI-F | 1 |
| **UNRESOLVED** | 20 |

## Typed packers (82)

| Packer family | Version | Test case | Empirical Type |
|---------------|---------|-----------|----------------|
| acprotect_std_Standard__installer | ? | . | **TYPE_I** |
| beroexepacker | 1.00.2017.01.27 | BEP_001_DEFAULT | **TYPE_I** |
| eronona | 1.0 | ERONONA_001_DEFAULT | **TYPE_I** |
| hackupx | 1.00 | HACKUPX_001_MUTATE | **TYPE_I** |
| mew | 1.1_SE | . | **TYPE_I** |
| npack | 1.1.300.2006 | . | **TYPE_I** |
| packman | 1.0 | . | **TYPE_I** |
| pe_diminisher | 0.1 | . | **TYPE_I** |
| pepacker | 1.0 | PEPACKER_001_DEFAULT | **TYPE_I** |
| rlpack | 1.21_Basic | . | **TYPE_I** |
| upx | 0.60 | UPX_V060_001_DEFAULT | **TYPE_I** |
| upx | 0.61 | UPX_V061_001_DEFAULT | **TYPE_I** |
| upx | 0.62 | UPX_V062_001_DEFAULT | **TYPE_I** |
| upx | 0.70 | UPX_V070_001_DEFAULT | **TYPE_I** |
| upx | 0.71 | UPX_V071_001_DEFAULT | **TYPE_I** |
| upx | 0.72 | UPX_V072_001_DEFAULT | **TYPE_I** |
| upx | 0.762b | UPX_V762BETA_001_DEFAULT | **TYPE_I** |
| upx | 0.763b | UPX_V763BETA_001_DEFAULT | **TYPE_I** |
| upx | 0.80 | UPX_V080_001_DEFAULT | **TYPE_I** |
| upx | 0.81 | UPX_V081_001_DEFAULT | **TYPE_I** |
| upx | 0.82 | UPX_V082_001_DEFAULT | **TYPE_I** |
| upx | 0.83 | UPX_V083_001_DEFAULT | **TYPE_I** |
| upx | 0.84 | UPX_V084_001_DEFAULT | **TYPE_I** |
| upx | 0.896b | UPX_V896BETA_001_DEFAULT | **TYPE_I** |
| upx | 0.90 | UPX_V090_001_DEFAULT | **TYPE_I** |
| upx | 0.92 | UPX_V092_001_DEFAULT | **TYPE_I** |
| upx | 0.93 | UPX_V093_001_DEFAULT | **TYPE_I** |
| upx | 0.94 | UPX_V094_001_DEFAULT | **TYPE_I** |
| upx | 0.99 | UPX_V099_001_DEFAULT | **TYPE_I** |
| upx | 0.991 | UPX_V0991_001_DEFAULT | **TYPE_I** |
| upx | 0.992 | UPX_V0992_001_DEFAULT | **TYPE_I** |
| upx | 0.993 | UPX_V0993_001_DEFAULT | **TYPE_I** |
| upx | 1.00 | UPX_V100_001_DEFAULT | **TYPE_I** |
| upx | 1.01 | UPX_V101_001_DEFAULT | **TYPE_I** |
| upx | 1.02 | UPX_V102_001_DEFAULT | **TYPE_I** |
| upx | 1.03 | UPX_V103_001_DEFAULT | **TYPE_I** |
| upx | 1.04 | UPX_V104_001_DEFAULT | **TYPE_I** |
| upx | 1.05 | UPX_V105_001_DEFAULT | **TYPE_I** |
| upx | 1.06 | UPX_V106_001_DEFAULT | **TYPE_I** |
| upx | 1.07 | UPX_V107_001_DEFAULT | **TYPE_I** |
| upx | 1.08 | UPX_V108_001_DEFAULT | **TYPE_I** |
| upx | 1.20 | UPX_V120_001_DEFAULT | **TYPE_I** |
| upx | 1.21 | UPX_V121_001_DEFAULT | **TYPE_I** |
| upx | 1.22 | UPX_V122_001_DEFAULT | **TYPE_I** |
| upx | 3.95 | UPX_V395_001_DEFAULT | **TYPE_I** |
| upx | 3.96 | UPX_V396_001_DEFAULT | **TYPE_I** |
| upx | 4.0.0 | UPX_V400_001_DEFAULT | **TYPE_I** |
| upx | 4.0.1 | UPX_V401_001_DEFAULT | **TYPE_I** |
| upx | 4.0.2 | UPX_V402_001_DEFAULT | **TYPE_I** |
| upx | 4.1.0 | UPX_V410_001_DEFAULT | **TYPE_I** |
| upx | 4.2.0 | UPX_V420_001_DEFAULT | **TYPE_I** |
| upx | 4.2.1 | UPX_V421_001_DEFAULT | **TYPE_I** |
| upx | 4.2.2 | UPX_V422_001_DEFAULT | **TYPE_I** |
| upx | 4.2.3 | UPX_V423_001_DEFAULT | **TYPE_I** |
| upx | 4.2.4 | UPX_V424_001_DEFAULT | **TYPE_I** |
| upx | 5.0.0 | UPX_V500_001_DEFAULT | **TYPE_I** |
| upx | 5.0.1 | UPX_V501_001_DEFAULT | **TYPE_I** |
| upx | 5.0.2 | UPX_V502_001_DEFAULT | **TYPE_I** |
| upx | 5.1.0 | UPX_001_DEFAULT | **TYPE_I** |
| upx | 5.1.1 | UPX_V511_001_DEFAULT | **TYPE_I** |
| upx_scrambler | 3.0.4 | . | **TYPE_I** |
| upx_scrambler | 306_unknown | . | **TYPE_I** |
| upx_scrambler_rc103_unknown | ? | . | **TYPE_I** |
| upx_scrambler_rc105_unknown | ? | . | **TYPE_I** |
| upx_scrambler_rc1_RC1 | ? | . | **TYPE_I** |
| upx_scrambler_rc1b10_RC1b10 | ? | . | **TYPE_I** |
| xcomp | 0.97 | XCOMP_001_DEFAULT | **TYPE_I** |
| yoda_protector | 1.0 | . | **TYPE_I** |
| kkrunchy | 0.23_alpha | KKRUNCHY_001_DEFAULT | **TYPE_II** |
| mpress | 1.27 | MPRESS_V127_001_DEFAULT | **TYPE_II** |
| mpress | 2.19 | MPRESS_001_DEFAULT | **TYPE_II** |
| yoda_crypter | 1.2 | . | **TYPE_II** |
| jdpack | 1.00 | . | **TYPE_III** |
| petite | 2.2 | PETITE_V22_001_DEFAULT | **TYPE_III** |
| petite | 2.3 | PETITE_V23_001_DEFAULT | **TYPE_III** |
| petite | 2.4 | PETITE_001_DEFAULT | **TYPE_III** |
| shrinker | 3.4_Demo | . | **TYPE_III** |
| exe32pack | 1.42 | EXE32PACK_001_DEFAULT | **TYPE_IV** |
| nspack | 3.7 | . | **TYPE_IV** |
| upack | 0.399__Brute | UPACK_001_DEFAULT | **TYPE_IV** |
| yoda_protector | 1.02 | . | **TYPE_IV** |
| pelock | 2.40 | . | **TYPE_VI-F** |

## Unresolved (20)

Genuine protectors the write→execute oracle cannot resolve to a Type (virtualization / section-mapped loading / non-executing). `protection_class` records the measurable mechanism.

| Packer family | Version | Test case | protection_class |
|---------------|---------|-----------|------------------|
| alienyze_protector | 1.4 | . | inconclusive |
| amber | 2.0 | AMBER_V2_002_REFLECTIVE | no_execution |
| armadillo | 252b2 | . | inconclusive |
| asm_guard | 2.9.4 | . | inconclusive |
| astral_pe | 1.6.0.0 | ASTRAL_001_DEFAULT_MUTATION | inconclusive |
| enigma_protector | 7.80_build_20250205 | ENIGMA_001_DEFAULT | inconclusive |
| fsg | 1.3 | FSG_V13_001_DEFAULT | inconclusive |
| kkrunchy | 0.23_alpha_2 | KKRUNCHY_V023A2_001_DEFAULT | mapped_execution |
| molebox | 4.6000 | MOLEBOX_001_DEFAULT | mapped_execution |
| obsidium | 1.5.2.11 | . | inconclusive |
| pezor | 3.3.0 | PEZOR_002_SELF_INJECT_32 | inconclusive |
| simpledpack | 0.5.3 | SIMPLEDPACK_V053_001_DEFAULT | no_execution |
| telock | 0.98 | . | inconclusive |
| themida | 3.2.4.34 | . | inconclusive |
| winupack | 0.39 | . | mapped_execution |
| yoda_crypter | 1.3 | . | inconclusive |
| yoda_protector | 1.01.2 | . | mapped_execution |
| yoda_protector | 1.03.2 | . | no_execution |
| yoda_protector | 1.03.3 | . | mapped_execution |
| zprotect | 1.4.2.0 | . | inconclusive |
