/// Reduce uses of typedefs of named structures to the name of the structure

virtual patch
virtual context
virtual org
virtual report

@td@
type T;
identifier S;
@@
(
- typedef struct S
+ struct S
  { ...
- } T;
+ };
|
  struct S;
- typedef struct S T;
)
@@
type td.T;
identifier td.S;
@@
- T
+ struct S

@@
type td.T;
identifier td.S;
@@
- const T
+ const struct S

/// Now structures declared with typedefs of opaque structs, one by one
@@
typedef dtrace_ecb_t;
@@
- dtrace_ecb_t
+ struct dtrace_ecb

@@
typedef dtrace_actdesc_t;
@@
- dtrace_actdesc_t
+ struct dtrace_actdesc

@@
typedef dtrace_state_t;
@@
- dtrace_state_t
+ struct dtrace_state

@@
typedef dtrace_vstate_t;
@@
- dtrace_vstate_t
+ struct dtrace_vstate

@@
typedef dtrace_mstate_t;
@@
- dtrace_mstate_t
+ struct dtrace_mstate

@@
typedef dtrace_task_t;
@@
- dtrace_task_t
+ struct dtrace_task

@@
typedef dtrace_psinfo_t;
@@
- dtrace_psinfo_t
+ struct dtrace_psinfo

@@
typedef dt_fbt_bl_entry_t;
@@
- dt_fbt_bl_entry_t
+ struct dt_fbt_bl_entry
