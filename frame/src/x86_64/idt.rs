//! x86_64 Interrupt Descriptor Table.
//!
//! Long-mode IDT entries are 16 bytes each. 32 CPU-exception vectors are
//! installed with interrupt gates pointing at `int_N` stubs from
//! `trap_entry.S`. Vectors 32..=255 remain "not present" — external
//! IRQs / IPIs land with the `interrupts/` crate in Stage 2.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// 64-bit IDT gate layout (Intel SDM Vol 3 §6.14).
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,       // low 3 bits; 0 = use current stack
    type_attr: u8, // P | DPL(2) | 0 | Type(4)
    offset_mid: u16,
    offset_high: u32,
    _zero: u32,
}

impl IdtEntry {
    const NULL: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        _zero: 0,
    };

    const fn new(handler: u64, selector: u16, ist: u8, type_attr: u8) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist,
            type_attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _zero: 0,
        }
    }
}

// SAFETY: `IdtEntry` is `#[repr(C, packed)]` POD; manual Debug elided because
// `missing_debug_implementations` is deny-by-default but we don't expose
// IdtEntry outside this module.
impl core::fmt::Debug for IdtEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdtEntry").finish_non_exhaustive()
    }
}

/// 10-byte LIDT pseudo-descriptor.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

impl core::fmt::Debug for IdtPointer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdtPointer").finish_non_exhaustive()
    }
}

const IDT_ENTRIES: usize = 256;

/// Interrupt-gate, present, DPL=0: 0x8E.
const GATE_INT_KERNEL: u8 = 0x8E;
/// Interrupt-gate, present, DPL=3: 0xEE. User-mode software
/// interrupts (`int 0x80` from CPL=3) require DPL=3 or they #GP.
const GATE_INT_USER: u8 = 0xEE;

use super::gdt::{IST_DF, IST_MC, IST_NMI, IST_VC, KCODE_SEL};

/// The IDT itself — 4 KiB.
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::NULL; IDT_ENTRIES];

// Declared by `trap_entry.S` — one symbol per vector.
extern "C" {
    fn int_0();
    fn int_1();
    fn int_2();
    fn int_3();
    fn int_4();
    fn int_5();
    fn int_6();
    fn int_7();
    fn int_8();
    fn int_9();
    fn int_10();
    fn int_11();
    fn int_12();
    fn int_13();
    fn int_14();
    fn int_15();
    fn int_16();
    fn int_17();
    fn int_18();
    fn int_19();
    fn int_20();
    fn int_21();
    fn int_22();
    fn int_23();
    fn int_24();
    fn int_25();
    fn int_26();
    fn int_27();
    fn int_28();
    fn int_29();
    fn int_30();
    fn int_31();

    // External IRQ stubs (32..=47) + spurious (255).
    fn int_32();
    fn int_33();
    fn int_34();
    fn int_35();
    fn int_36();
    fn int_37();
    fn int_38();
    fn int_39();
    fn int_40();
    fn int_41();
    fn int_42();
    fn int_43();
    fn int_44();
    fn int_45();
    fn int_46();
    fn int_47();
    // Allocator-pool vectors 48..=254 used for MSI/MSI-X delivery.
    fn int_48();
    fn int_49();
    fn int_50();
    fn int_51();
    fn int_52();
    fn int_53();
    fn int_54();
    fn int_55();
    fn int_56();
    fn int_57();
    fn int_58();
    fn int_59();
    fn int_60();
    fn int_61();
    fn int_62();
    fn int_63();
    fn int_64();
    fn int_65();
    fn int_66();
    fn int_67();
    fn int_68();
    fn int_69();
    fn int_70();
    fn int_71();
    fn int_72();
    fn int_73();
    fn int_74();
    fn int_75();
    fn int_76();
    fn int_77();
    fn int_78();
    fn int_79();
    fn int_80();
    fn int_81();
    fn int_82();
    fn int_83();
    fn int_84();
    fn int_85();
    fn int_86();
    fn int_87();
    fn int_88();
    fn int_89();
    fn int_90();
    fn int_91();
    fn int_92();
    fn int_93();
    fn int_94();
    fn int_95();
    fn int_96();
    fn int_97();
    fn int_98();
    fn int_99();
    fn int_100();
    fn int_101();
    fn int_102();
    fn int_103();
    fn int_104();
    fn int_105();
    fn int_106();
    fn int_107();
    fn int_108();
    fn int_109();
    fn int_110();
    fn int_111();
    fn int_112();
    fn int_113();
    fn int_114();
    fn int_115();
    fn int_116();
    fn int_117();
    fn int_118();
    fn int_119();
    fn int_120();
    fn int_121();
    fn int_122();
    fn int_123();
    fn int_124();
    fn int_125();
    fn int_126();
    fn int_127();
    fn int_128();
    fn int_129();
    fn int_130();
    fn int_131();
    fn int_132();
    fn int_133();
    fn int_134();
    fn int_135();
    fn int_136();
    fn int_137();
    fn int_138();
    fn int_139();
    fn int_140();
    fn int_141();
    fn int_142();
    fn int_143();
    fn int_144();
    fn int_145();
    fn int_146();
    fn int_147();
    fn int_148();
    fn int_149();
    fn int_150();
    fn int_151();
    fn int_152();
    fn int_153();
    fn int_154();
    fn int_155();
    fn int_156();
    fn int_157();
    fn int_158();
    fn int_159();
    fn int_160();
    fn int_161();
    fn int_162();
    fn int_163();
    fn int_164();
    fn int_165();
    fn int_166();
    fn int_167();
    fn int_168();
    fn int_169();
    fn int_170();
    fn int_171();
    fn int_172();
    fn int_173();
    fn int_174();
    fn int_175();
    fn int_176();
    fn int_177();
    fn int_178();
    fn int_179();
    fn int_180();
    fn int_181();
    fn int_182();
    fn int_183();
    fn int_184();
    fn int_185();
    fn int_186();
    fn int_187();
    fn int_188();
    fn int_189();
    fn int_190();
    fn int_191();
    fn int_192();
    fn int_193();
    fn int_194();
    fn int_195();
    fn int_196();
    fn int_197();
    fn int_198();
    fn int_199();
    fn int_200();
    fn int_201();
    fn int_202();
    fn int_203();
    fn int_204();
    fn int_205();
    fn int_206();
    fn int_207();
    fn int_208();
    fn int_209();
    fn int_210();
    fn int_211();
    fn int_212();
    fn int_213();
    fn int_214();
    fn int_215();
    fn int_216();
    fn int_217();
    fn int_218();
    fn int_219();
    fn int_220();
    fn int_221();
    fn int_222();
    fn int_223();
    fn int_224();
    fn int_225();
    fn int_226();
    fn int_227();
    fn int_228();
    fn int_229();
    fn int_230();
    fn int_231();
    fn int_232();
    fn int_233();
    fn int_234();
    fn int_235();
    fn int_236();
    fn int_237();
    fn int_238();
    fn int_239();
    fn int_240();
    fn int_241();
    fn int_242();
    fn int_243();
    fn int_244();
    fn int_245();
    fn int_246();
    fn int_247();
    fn int_248();
    fn int_249();
    fn int_250();
    fn int_251();
    fn int_252();
    fn int_253();
    fn int_254();
    fn int_255();
}

fn install(vec: usize, handler: unsafe extern "C" fn()) {
    install_with_ist(vec, handler, 0);
}

fn install_with_ist(vec: usize, handler: unsafe extern "C" fn(), ist: u8) {
    install_full(vec, handler, ist, GATE_INT_KERNEL);
}

fn install_full(vec: usize, handler: unsafe extern "C" fn(), ist: u8, gate: u8) {
    let entry = IdtEntry::new(handler as u64, KCODE_SEL, ist, gate);
    // SAFETY: IDT is accessed only on the BSP during Stage-1 bring-up, before
    // any other CPU or interrupt handler can observe it. The write happens
    // before `lidt`, and the entry layout matches the hardware spec.
    unsafe {
        core::ptr::addr_of_mut!(IDT)
            .cast::<IdtEntry>()
            .add(vec)
            .write(entry);
    }
}

/// Build and load the IDT. Called from `init_traps`.
///
/// # Safety
/// Must be called exactly once, on the BSP, before anything that could
/// generate a CPU exception we want to survive.
pub unsafe fn init() {
    // Fill the 32 CPU-exception slots. The rest stay zero/NULL;
    // unhandled external IRQs would cause a triple-fault, but Stage 1
    // leaves interrupts masked until `interrupts/` lands.
    install(0, int_0);
    install(1, int_1);
    install_with_ist(2, int_2, IST_NMI); // NMI runs on its own stack
    install(3, int_3);
    install(4, int_4);
    install(5, int_5);
    install(6, int_6);
    install(7, int_7);
    install_with_ist(8, int_8, IST_DF); // #DF must not re-double-fault
    install(9, int_9);
    install(10, int_10);
    install(11, int_11);
    install(12, int_12);
    install(13, int_13);
    install(14, int_14);
    install(15, int_15);
    install(16, int_16);
    install(17, int_17);
    install_with_ist(18, int_18, IST_MC); // #MC is asynchronous, own stack
    install(19, int_19);
    install(20, int_20);
    install(21, int_21);
    install(22, int_22);
    install(23, int_23);
    install(24, int_24);
    install(25, int_25);
    install(26, int_26);
    install(27, int_27);
    install(28, int_28);
    install_with_ist(29, int_29, IST_VC); // #VC (SEV-ES) own stack
    install(30, int_30);
    install(31, int_31);

    // External IRQs 32..=254 + spurious 255. The full range is
    // populated so the MSI/MSI-X allocator (vectors 48..=240) can
    // hand out any vector without #GP'ing on first IRQ delivery.
    install(32, int_32);
    install(33, int_33);
    install(34, int_34);
    install(35, int_35);
    install(36, int_36);
    install(37, int_37);
    install(38, int_38);
    install(39, int_39);
    install(40, int_40);
    install(41, int_41);
    install(42, int_42);
    install(43, int_43);
    install(44, int_44);
    install(45, int_45);
    install(46, int_46);
    install(47, int_47);
    install(48, int_48);
    install(49, int_49);
    install(50, int_50);
    install(51, int_51);
    install(52, int_52);
    install(53, int_53);
    install(54, int_54);
    install(55, int_55);
    install(56, int_56);
    install(57, int_57);
    install(58, int_58);
    install(59, int_59);
    install(60, int_60);
    install(61, int_61);
    install(62, int_62);
    install(63, int_63);
    install(64, int_64);
    install(65, int_65);
    install(66, int_66);
    install(67, int_67);
    install(68, int_68);
    install(69, int_69);
    install(70, int_70);
    install(71, int_71);
    install(72, int_72);
    install(73, int_73);
    install(74, int_74);
    install(75, int_75);
    install(76, int_76);
    install(77, int_77);
    install(78, int_78);
    install(79, int_79);
    install(80, int_80);
    install(81, int_81);
    install(82, int_82);
    install(83, int_83);
    install(84, int_84);
    install(85, int_85);
    install(86, int_86);
    install(87, int_87);
    install(88, int_88);
    install(89, int_89);
    install(90, int_90);
    install(91, int_91);
    install(92, int_92);
    install(93, int_93);
    install(94, int_94);
    install(95, int_95);
    install(96, int_96);
    install(97, int_97);
    install(98, int_98);
    install(99, int_99);
    install(100, int_100);
    install(101, int_101);
    install(102, int_102);
    install(103, int_103);
    install(104, int_104);
    install(105, int_105);
    install(106, int_106);
    install(107, int_107);
    install(108, int_108);
    install(109, int_109);
    install(110, int_110);
    install(111, int_111);
    install(112, int_112);
    install(113, int_113);
    install(114, int_114);
    install(115, int_115);
    install(116, int_116);
    install(117, int_117);
    install(118, int_118);
    install(119, int_119);
    install(120, int_120);
    install(121, int_121);
    install(122, int_122);
    install(123, int_123);
    install(124, int_124);
    install(125, int_125);
    install(126, int_126);
    install(127, int_127);
    // Software-interrupt syscall gate — `int 0x80` routes here.
    // DPL=3 so user mode (CPL=3) can trigger it; kernel mode also
    // works at any CPL.
    install_full(128, int_128, 0, GATE_INT_USER);
    install(129, int_129);
    install(130, int_130);
    install(131, int_131);
    install(132, int_132);
    install(133, int_133);
    install(134, int_134);
    install(135, int_135);
    install(136, int_136);
    install(137, int_137);
    install(138, int_138);
    install(139, int_139);
    install(140, int_140);
    install(141, int_141);
    install(142, int_142);
    install(143, int_143);
    install(144, int_144);
    install(145, int_145);
    install(146, int_146);
    install(147, int_147);
    install(148, int_148);
    install(149, int_149);
    install(150, int_150);
    install(151, int_151);
    install(152, int_152);
    install(153, int_153);
    install(154, int_154);
    install(155, int_155);
    install(156, int_156);
    install(157, int_157);
    install(158, int_158);
    install(159, int_159);
    install(160, int_160);
    install(161, int_161);
    install(162, int_162);
    install(163, int_163);
    install(164, int_164);
    install(165, int_165);
    install(166, int_166);
    install(167, int_167);
    install(168, int_168);
    install(169, int_169);
    install(170, int_170);
    install(171, int_171);
    install(172, int_172);
    install(173, int_173);
    install(174, int_174);
    install(175, int_175);
    install(176, int_176);
    install(177, int_177);
    install(178, int_178);
    install(179, int_179);
    install(180, int_180);
    install(181, int_181);
    install(182, int_182);
    install(183, int_183);
    install(184, int_184);
    install(185, int_185);
    install(186, int_186);
    install(187, int_187);
    install(188, int_188);
    install(189, int_189);
    install(190, int_190);
    install(191, int_191);
    install(192, int_192);
    install(193, int_193);
    install(194, int_194);
    install(195, int_195);
    install(196, int_196);
    install(197, int_197);
    install(198, int_198);
    install(199, int_199);
    install(200, int_200);
    install(201, int_201);
    install(202, int_202);
    install(203, int_203);
    install(204, int_204);
    install(205, int_205);
    install(206, int_206);
    install(207, int_207);
    install(208, int_208);
    install(209, int_209);
    install(210, int_210);
    install(211, int_211);
    install(212, int_212);
    install(213, int_213);
    install(214, int_214);
    install(215, int_215);
    install(216, int_216);
    install(217, int_217);
    install(218, int_218);
    install(219, int_219);
    install(220, int_220);
    install(221, int_221);
    install(222, int_222);
    install(223, int_223);
    install(224, int_224);
    install(225, int_225);
    install(226, int_226);
    install(227, int_227);
    install(228, int_228);
    install(229, int_229);
    install(230, int_230);
    install(231, int_231);
    install(232, int_232);
    install(233, int_233);
    install(234, int_234);
    install(235, int_235);
    install(236, int_236);
    install(237, int_237);
    install(238, int_238);
    install(239, int_239);
    install(240, int_240);
    install(241, int_241);
    install(242, int_242);
    install(243, int_243);
    install(244, int_244);
    install(245, int_245);
    install(246, int_246);
    install(247, int_247);
    install(248, int_248);
    install(249, int_249);
    install(250, int_250);
    install(251, int_251);
    install(252, int_252);
    install(253, int_253);
    install(254, int_254);
    install(255, int_255);

    // Build the LIDT descriptor and load it.
    let ptr = IdtPointer {
        limit: (IDT_ENTRIES * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };

    compiler_fence(Ordering::SeqCst);
    // SAFETY: `lidt` with a valid 10-byte pseudo-descriptor installs the
    // IDT. The compiler_fence pair follows arch/ §4.
    unsafe {
        asm!("lidt [{p}]", p = in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
}

/// Load the BSP-built IDT register on this CPU. Used by AP bring-up:
/// the IDT entries are populated once on the BSP, but each CPU's
/// IDTR is per-CPU and must be loaded individually.
///
/// # Safety
/// `init` must have already populated the IDT on the BSP. Caller
/// must be at CPL=0 with interrupts disabled.
pub unsafe fn load_idtr_ap() {
    let ptr = IdtPointer {
        limit: (IDT_ENTRIES * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    compiler_fence(Ordering::SeqCst);
    // SAFETY: same as init's lidt — IDT is BSP-built and immutable
    // post-init.
    unsafe {
        asm!("lidt [{p}]", p = in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
