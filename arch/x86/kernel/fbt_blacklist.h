/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Functions used in die notifier chain calling.
 */
BL_SENTRY(void *, notify_die)
BL_DENTRY(void *, notifier_call_chain)
BL_SENTRY(typeof(atomic_notifier_call_chain), atomic_notifier_call_chain)
BL_SENTRY(typeof(raw_notifier_call_chain_robust), raw_notifier_call_chain_robust)
BL_SENTRY(typeof(raw_notifier_call_chain), raw_notifier_call_chain)
BL_DENTRY(void *, hw_breakpoint_exceptions_notify)
BL_DENTRY(void *, kprobe_exceptions_notify)

/*
 * Functions used to update vtime in probe context.
 */
BL_SENTRY(typeof(ktime_get_raw_fast_ns), ktime_get_raw_fast_ns)
BL_DENTRY(void *, raw_read_seqcount)
BL_DENTRY(void *, read_seqcount_retry)
BL_DENTRY(void *, __read_seqcount_retry)

/* xen_clocksource */
BL_DENTRY(void *, xen_clocksource_get_cycles)
BL_DENTRY(void *, xen_clocksource_read)
BL_DENTRY(void *, pvclock_clocksource_read)
BL_DENTRY(void *, pvclock_touch_watchdogs)
BL_DENTRY(void *, touch_softlockup_watchdog_sync)
BL_DENTRY(void *, clocksource_touch_watchdog)
BL_DENTRY(void *, clocksource_resume_watchdog)
BL_DENTRY(void *, reset_hung_task_detector)
/* clocksource_tsc */
BL_DENTRY(void *, read_tsc)
BL_DENTRY(void *, get_cycles)
/* clocksource_hpet */
BL_DENTRY(void *, read_hpet)
BL_DENTRY(void *, hpet_readl)
/* kvm_clock */
BL_DENTRY(void *, kvm_clock_get_cycles)
BL_DENTRY(void *, kvm_clock_read)

/*
 * Functions used in trap handling.
 */
BL_DENTRY(void *, fixup_exception)
BL_DENTRY(void *, paranoid_entry)
BL_DENTRY(void *, kgdb_ll_trap)
BL_DENTRY(void *, error_entry)
BL_DENTRY(void *, xen_int3)
BL_DENTRY(void *, do_int3)
BL_DENTRY(void *, ftrace_int3_handler)
BL_DENTRY(typeof(poke_int3_handler), poke_int3_handler)
BL_DENTRY(void *, fixup_bad_iret)
BL_DENTRY(void *, xen_adjust_exception_frame)
BL_DENTRY(void *, paravirt_nop)
BL_DENTRY(void *, ist_enter)
BL_DENTRY(void *, rcu_nmi_enter)
BL_DENTRY(void *, rcu_dynticks_curr_cpu_in_eqs)
BL_DENTRY(void *, rcu_dynticks_eqs_exit)
BL_DENTRY(void *, trace_rcu_dyntick)
BL_DENTRY(void *, rcu_nmi_exit)
BL_DENTRY(void *, rcu_irq_exit)
BL_DENTRY(void *, rcu_nmi_exit_common)
BL_DENTRY(void *, rcu_dynticks_eqs_enter)
BL_DENTRY(void *, ist_exit)

/*
 * Functions used in page fault handling.
 */
BL_DENTRY(void *, do_kern_addr_fault)
BL_DENTRY(void *, do_kern_addr_fault)
BL_DENTRY(void *, handle_page_fault)
BL_DENTRY(void *, huge_page_mask)
BL_DENTRY(void *, mmap_address_hint_valid)
BL_DENTRY(void *, vm_start_gap)
BL_DENTRY(void *, hugetlb_get_unmapped_area_bottomup)
BL_DENTRY(void *, hugetlb_get_unmapped_area_topdown)
BL_DENTRY(void *, down_read_trylock)
BL_DENTRY(void *, __get_user_pages_fast)
BL_DENTRY(void *, gup_pud_range)
BL_DENTRY(void *, gup_huge_pud)
BL_DENTRY(void *, gup_pmd_range)
BL_DENTRY(void *, gup_huge_pmd)
BL_DENTRY(void *, gup_pte_range)
BL_DENTRY(void *, pte_mfn_to_pfn)

/*
 * Functions used under 4.12 idr_find
 */
BL_DENTRY(void *, idr_find)
BL_DENTRY(void *, find_next_bit)
BL_DENTRY(void *, _find_next_bit)
BL_DENTRY(void *, radix_tree_lookup)
BL_DENTRY(void *, __radix_tree_lookup)
BL_DENTRY(void *, radix_tree_load_root)
BL_DENTRY(void *, radix_tree_descend)
BL_DENTRY(void *, is_sibling_entry)
